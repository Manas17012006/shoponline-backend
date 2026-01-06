// backend/controllers/auth.controller.js
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userModel = require("../models/userModel.model");
const transporter = require("../config/nodemailer");
//register
const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res
      .status(400)
      .send({ success: false, message: "All fieldsrequired" });
  }
  try {
    const exist = await userModel.findOne({ email });
    if (exist) {
      return res
        .status(200)
        .send({ success: false, message: "User already Registered " });
    }
    const pass = bcrypt.hashSync(password, 8);
    const user = await userModel.create({
      name: name,
      email: email,
      password: pass,
    });

    //generate jwt token
    // const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:"7d"});

    // //add token to the response,,,,cookie ka naam cookie h mere bhai
    //     res.cookie("token", token, {
    //         httpOnly: true,
    //         secure: process.env.NODE_ENV === "production",
    //         sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    //         maxAge: 7 * 24 * 60 * 60 * 1000,
    //         path: "/",
    //     });
    //sending welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to E-COMMERCE",
      html: `<div style="font-family:Arial,sans-serif;
            padding:15px;
            color:#333;">

  <h2 style="margin-bottom:8px;">
    Welcome to ShopOnline 🎉
  </h2>

  <p style="font-size:14px;">
    Your account has been successfully created.
  </p>

  <p style="font-size:13px;color:#555;">
    Login to get started and enjoy shopping with us.
  </p>

  <p style="margin-top:15px;font-size:13px;">
    — Team <strong>ShopOnline</strong>
  </p>

</div>
`,
    };
    await transporter.sendMail(mailOptions);
    return res.status(201).send({ success: true });
  } catch (err) {
    return res.status(400).send({ success: false, message: err.message });
  }
};

//login
const login = async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields required"
    });
  }
  
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User Not Found, Register first!"
      });
    }
    
    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Incorrect Password"
      });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    
    user.token = token;
    await user.save();
    
    return res.status(200).json({
      success: true,
      message: "Login successful",
      token: token,  // Important!
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
    
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Server error: " + err.message
    });
  }
};
//logout
const logout = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await userModel.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }
    user.isVerified = false;
    user.token="";
    await user.save();
    // res.clearCookie("token", {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    // });
    return res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    return res.status(400).send({ success: false, message: err.message });
  }
};

async function sendVerifyOtp(req, res) {
  try {
    const userId = req.userId;

    const user = await userModel.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // if (user.isVerified) {
    //   return res.json({
    //     success: false,
    //     message: "User already verified",
    //   });
    // }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.otp = otp;
    user.otpExp = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Verification OTP",
      html: `<div style="font-family:Arial,sans-serif;
            padding:15px;
            text-align:center;
            color:#333;">

  <h2 style="margin-bottom:8px;">OTP Verification</h2>

  <p style="font-size:14px;">
    Your OTP is
  </p>

  <div style="font-size:24px;
              font-weight:bold;
              letter-spacing:4px;
              margin:10px 0;">
    ${otp}
  </div>

  <p style="font-size:12px;color:#777;">
    Please do not share this OTP with anyone.
  </p>

</div>
`,
    };

    await transporter.sendMail(mailOption);

    return res.json({
      success: true,
      message: "OTP sent to your email",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
}
async function verifyEmail(req, res) {
  try {
    const { otp } = req.body;
    const userId = req.userId;

    if (!otp) {
      return res.status(400).json({
        success: false,
        message: "OTP is required",
      });
    }

    const user = await userModel.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (!user.otp || user.otp.toString().trim() !== otp.toString().trim()) {
      return res.json({
        success: false,
        message: "Incorrect OTP",
      });
    }

    if (user.otpExp < Date.now()) {
      return res.json({
        success: false,
        message: "OTP expired",
      });
    }

    user.isVerified = true;
    user.otp = "";
    user.otpExp = "";
    await user.save();

    return res.json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
}
//check if authentiacated
async function isAuthenticated(req, res) {
  try {
    return res.json({ success: true });
  } catch (err) {
    return res.status(400).send({ success: false, message: err.message });
  }
}

//send password Reset otp
async function sendResetOtp(req, res) {
  const { email } = req.body;
  if (!email) {
    return res.json({ success: false, message: "Email is required" });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "Email Not found" });
    }
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.resetOtp = otp;
    user.resetOtpExp = Date.now() + 15 * 60 * 1000;
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Resest OTP",
      html: `<h1>Your OTP for resetting the password is ${otp}</h1>`,
    };
    await transporter.sendMail(mailOption);
    return res
      .status(200)
      .send({ success: true, message: "Otp sent to your email" });
  } catch (err) {
    return res.status(400).send({ success: false, message: err.message });
  }
}

async function resetPassword(req, res) {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.json({ success: false, message: "All fields are required" });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User Not found" });
    }
    if (user.resetOtp === "" || user.resetOtp != otp) {
      return res.json({ success: false, message: "Incorrect OTP" });
    }
    if (user.resetOtpExp < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }
    const hashed = bcrypt.hashSync(newPassword, 8);
    user.resetOtp = "";
    user.resetOtpExp = "";
    user.password = hashed;
    await user.save();
    return res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    return res.status(400).send({ success: false, message: err.message });
  }
}
//export all functions

module.exports = {
  register,
  login,
  logout,
  sendVerifyOtp,
  verifyEmail,
  isAuthenticated,
  sendResetOtp,
  resetPassword,
};
