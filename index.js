require('dotenv').config();
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');  // For webhook verification
const Shopify = require('shopify-api-node');

const app = express();
app.use(express.json());  // Parse JSON bodies for webhooks



// Endpoint to generate Fygaro payment link and redirect
app.get('/pay', async (req, res) => {
    const { shop, variant_id, quantity } = req.query;
    const shopify = new Shopify({
        shopName: process.env.SHOPIFY_STORE_URL,
        accessToken: process.env.SHOPIFY_API_TOKEN
    });

    try {
        const order = await shopify.order.create({
            line_items: [{
                variant_id: parseInt(variant_id),
                quantity: parseInt(quantity),
            }],
            financial_status: 'pending'
        });

        const amount = order.total_price; // Or calculate manually
        const currency = order.currency; // e.g., 'USD'
        const customReference = order.name; // Use order name for tracking

        // Build Fygaro payment URL
        const paymentUrl = `${process.env.FYGARO_BUTTON_URL}?amount=${amount}&client_reference=${customReference}`;

        // Redirect to Fygaro
        res.redirect(paymentUrl);
    } catch (error) {
        console.error('Error creating order:', error);
    }
});

// Endpoint for Fygaro return URL (after payment)
app.get('/confirm', async (req, res) => {
    const customReference = req.query.customReference;  // Shopify order name

    // Optional: Update order here if needed, but rely on webhook for reliability
    res.redirect(`https://${process.env.SHOPIFY_STORE_URL}/orders/${customReference}`);  // Redirect back to Shopify thank-you
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