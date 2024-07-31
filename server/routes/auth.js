const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/User');

// Ruta para crear nuevos usuarios (protegida con la clave del dueño)
router.post('/create-user', async (req, res) => {
    const { username, password, ownerKey } = req.body;

    if (ownerKey !== '1913') {
        return res.status(403).json({ message: 'Access Denied' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const secret = speakeasy.generateSecret({ length: 20 });

        const newUser = new User({
            username,
            password: hashedPassword,
            twoFactorSecret: secret.base32
        });

        await newUser.save();

        qrcode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
            if (err) {
                return res.status(500).json({ error: 'Error generating QR code' });
            }

            res.status(201).json({ 
                message: 'User created successfully', 
                qrCodeUrl: dataUrl 
            });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Ruta para iniciar sesión
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Ruta para obtener el código OTP para 2FA
router.post('/2fa', (req, res) => {
    const secret = speakeasy.generateSecret({ length: 20 });
    res.json({ secret: secret.base32 });
});

// Ruta para verificar el código OTP
router.post('/verify-2fa', (req, res) => {
    const { token, secret } = req.body;

    const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token
    });

    if (verified) {
        res.json({ message: '2FA success' });
    } else {
        res.status(400).json({ message: '2FA failed' });
    }
});

module.exports = router;
