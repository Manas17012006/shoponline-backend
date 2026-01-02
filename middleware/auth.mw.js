const userModel = require('../models/userModel.model');

const userauth = async (req, res, next) => {
  try {
    // Get token either from header or req.body (your choice)
    const token = req.headers.authorization?.split(" ")[1] || req.body.token;
    if (!token) {
      return res.status(401).json({ success: false, message: "Please login to get started!" });
    }

    // Find user by token stored in DB
    const user = await userModel.findOne({ token: token });
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    // Set req.userId for next handlers
    req.userId = user._id;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid token" });
  }
};

module.exports = { userauth };
