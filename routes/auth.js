const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const authMiddleware = require('../middleware/authMiddleware');
const router = express.Router();

router.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    console.log(req.body);
    const userExist = await User.findOne({ username });
    if (userExist) {
        return res.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.json({ message: "User created successfully" });
});

router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
});
router.get("/profile", authMiddleware, async (req, res) => {
    try {
        // Log the user ID to check if it's passed correctly
        console.log("User ID from token:", req.user.id);

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Log the user data for debugging purposes
        console.log("Fetched User:", user);
        
        res.json({ user });
    } catch (error) {
        console.log("Error in /profile:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

 module.exports = router;