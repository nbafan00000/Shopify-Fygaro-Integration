import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import Shopify from 'shopify-api-node';
import jwt from 'jsonwebtoken';

// Shopify API (v12+ is ESM only)
import { shopifyApi, ApiVersion } from '@shopify/shopify-api';
import '@shopify/shopify-api/adapters/node'; // registers the Node adapter


const app = express();
app.use(express.json());  // Parse JSON bodies for webhooks
var order = null;


// Endpoint to generate Fygaro payment link and redirect
app.get('/pay', async (req, res) => {
    const { customer_id, variant_id, quantity, line_items } = req.query;
    const shopify = new Shopify({
        shopName: process.env.SHOPIFY_STORE_URL,
        accessToken: process.env.SHOPIFY_API_TOKEN
    });

    try {
        if (line_items) {
            console.log('Creating order with multiple line items');
            const parsedLineItems = JSON.parse(decodeURIComponent(line_items || '[]'));
            if (!Array.isArray(parsedLineItems) || parsedLineItems.length === 0) {
                throw new Error('Invalid line items');
            }
            order = await shopify.order.create({
                line_items: parsedLineItems,
                customer_id: parseInt(customer_id),
                financial_status: 'pending'
            });
        }
        else {
            console.log('Creating order with single line item');
            order = await shopify.order.create({
                line_items: [{
                    variant_id: parseInt(variant_id),
                    quantity: parseInt(quantity),
                }],
                customer_id: parseInt(customer_id),
                financial_status: 'pending'
            });
        }

        const amount = order.total_price; // Or calculate manually
        const currency = order.currency; // e.g., 'USD'
        const customReference = order.name; // Use order name for tracking

        // Generate JWT (header, payload, signature)
        const header = {
            alg: 'HS256',
            typ: 'JWT',
            kid: process.env.FYGARO_API_KEY,
        };

        const payload = {
            amount, // Required: string with up to 2 decimals
            currency, // Optional: defaults to button's currency
            custom_reference: customReference, // Optional: for webhook tracking
        };

        const token = jwt.sign(payload, process.env.FYGARO_SECRET, { header });

        // Build and redirect to Fygaro URL
        const paymentUrl = `${process.env.FYGARO_BUTTON_URL}?jwt=${token}`;

        // Redirect to Fygaro
        res.redirect(paymentUrl);
    } catch (error) {
        console.error('Error creating order:', error);
    }
});

// Endpoint to handle return from Fygaro and redirect to Shopify thank-you page
app.get('/confirm', async (req, res) => {
    const orderId = req.query.customReference; // Order ID from Fygaro
    console.log('Fetching status URL for order ID:', orderId);

    try {
        const shopify = shopifyApi({
            apiKey: process.env.SHOPIFY_API_TOKEN,
            apiSecretKey: process.env.SHOPIFY_API_SECRET,
            scopes: ['read_orders', 'write_orders'],
            hostName: process.env.HOST.replace(/https?:\/\//, ''),
            apiVersion: ApiVersion.October24, // Keep for 2024-10 compatibility
        });

        const session = {
            shop: process.env.SHOPIFY_STORE_URL,
            accessToken: process.env.SHOPIFY_API_TOKEN,
        };

        const client = new shopify.clients.Graphql({ session });

        // Directly query the Order for statusPageUrl (2024-10 field name)
        const orderQuery = `
      query getOrderStatusUrl($id: ID!) {
        order(id: $id) {
          statusPageUrl  # Changed from orderStatusUrl
        }
      }
    `;

        const orderGid = `gid://shopify/Order/${orderId}`;
        const orderResponse = await client.query({
            data: {
                query: orderQuery,
                variables: { id: orderGid },
            },
        });

        const orderData = orderResponse.body.data.order;
        if (!orderData || !orderData.statusPageUrl) {
            throw new Error('Order not found or status URL unavailable—verify ID and payment completion');
        }

        const statusPageUrl = orderData.statusPageUrl;
        res.redirect(statusPageUrl); // Redirect to thank-you page
    } catch (error) {
        console.error('Error:', error);
        res.redirect(`https://${process.env.SHOPIFY_STORE_URL}/account/orders`); // Fallback (login required)
    }
});

// Webhook endpoint for Fygaro notifications (on successful payment)

app.post('/webhook', (req, res) => {
    const signature = req.headers['fygaro-signature'];
    const keyId = req.headers['fygaro-key-id'];
    const rawBody = JSON.stringify(req.body);

    // Verify signature (DIY method for Node.js)
    const parts = signature.split(',').reduce((acc, part) => {
        const [k, v] = part.trim().split('=');
        if (k === 't') acc.timestamp = v;
        if (k === 'v1') acc.hashes.push(v);
        return acc;
    }, { timestamp: null, hashes: [] });

    if (!parts.timestamp || parts.hashes.length === 0 || keyId !== process.env.FYGARO_API_KEY) {
        return res.status(400).send('Invalid webhook');
    }

    // Replay protection: Check timestamp within 5 min
    if (Math.abs(Date.now() / 1000 - parseInt(parts.timestamp)) > 300) {
        return res.status(400).send('Stale timestamp');
    }

    const message = `${parts.timestamp}.${rawBody}`;
    const expectedHash = crypto.createHmac('sha256', process.env.FYGARO_HOOK_SECRET).update(message).digest('hex');

    const isValid = parts.hashes.some(hash => crypto.timingSafeEqual(Buffer.from(expectedHash), Buffer.from(hash)));
    if (!isValid) {
        return res.status(400).send('Invalid signature');
    }

    // Signature valid: Update Shopify order
    const customReference = req.body.customReference;  // Order name
    shopify.put(`/admin/api/2024-10/orders/${customReference}/transactions.json`, {
        transaction: { kind: 'sale', status: 'success', amount: req.body.amount }
    }, (err) => {
        if (err) console.error(err);
    });

    // Mark order as paid
    shopify.put(`/admin/api/2024-10/orders/${customReference}.json`, { order: { financial_status: 'paid' } }, (err) => {
        if (err) console.error(err);
    });

    res.status(200).send('OK');
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));