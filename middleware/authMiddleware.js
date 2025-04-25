const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    // Ensure the "Authorization" header exists
    const token = req.headers["authorization"];

    // Check if the token exists and starts with "Bearer "
    if (!token || !token.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    // Extract token from 'Bearer <token>'
    const actualToken = token.split(" ")[1];

    // Log the extracted token for debugging
    console.log('Extracted Token:', actualToken);

    try {
        // Verify the token and attach user info to the request
        const decoded = jwt.verify(actualToken, process.env.SECRET_KEY);
        req.user = decoded; // Attach user data to the request
        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        return res.status(401).json({ message: "Unauthorized: Invalid token" });
    }
};

module.exports = authMiddleware;
