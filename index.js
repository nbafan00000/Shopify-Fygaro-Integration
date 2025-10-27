require('dotenv').config();
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');  // For webhook verification
const Shopify = require('shopify-node-api');

const app = express();
app.use(express.json());  // Parse JSON bodies for webhooks

const shopify = new Shopify({
    shop: process.env.SHOPIFY_STORE_URL,
    access_token: process.env.SHOPIFY_API_TOKEN
});

// Endpoint to generate Fygaro payment link and redirect
app.get('/pay', async (req, res) => {
    const orderId = req.query.order_id;
    const orderName = req.query.order_name;

    try {
        // Fetch order details from Shopify
        const order = await new Promise((resolve, reject) => {
            shopify.get(`/admin/api/2024-10/orders/${orderId}.json`, (err, data) => {
                if (err) reject(err);
                resolve(data.order);
            });
        });

        const amount = order.total_price;
        const currency = order.currency;
        const customReference = orderName;  // Use Shopify order name as reference

        // Option 1: Simple pre-filled URL (editable by user)
        // let fygaroUrl = `${process.env.FYGARO_BUTTON_URL}?amount=${encodeURIComponent(amount)}&client_reference=${encodeURIComponent(customReference)}`;

        // Option 2: Secure JWT URL (non-editable, recommended for Pro plan)
        const header = { alg: 'HS256', typ: 'JWT', kid: process.env.FYGARO_API_KEY };
        const payload = { amount: amount.toFixed(2), currency, custom_reference: customReference };
        const token = jwt.sign(payload, process.env.FYGARO_SECRET, { header });
        const fygaroUrl = `${process.env.FYGARO_BUTTON_URL}?jwt=${token}`;

        // Redirect to Fygaro
        res.redirect(fygaroUrl);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error generating payment link');
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