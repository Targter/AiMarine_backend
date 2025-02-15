import mongoose from "mongoose";
import TempUser from "../modles/Tempuser.moddles.js";
import bcrypt from "bcrypt";
import User from "../modles/useSchema.js";
import nodemailer from "nodemailer";

// Generate access and refresh token
const generateAccessandRefreshToken = async (UserId) => {
  try {
    const user = await User.findById(UserId);
    const AccessToken = await user.GenerateAccessToken();
    const RefreshToken = await user.GenerateRefreshToken();
    // giving the value of refreshToken
    user.refreshToken = RefreshToken;

    // it save this to our database  require the password to do this thats why we done this
    await user.save({ validateBeforeSave: false });

    return { AccessToken, RefreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating the access and refresh Token"
    );
  }
};
// Generate a 6-digit OTP
const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// export default generateOtp;
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  // secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
  // console.log("process",process.env.EMAIL_USER);
});
//   Register user
export const RegisterUser = async (req, res) => {
  try {
    const { email } = req.body;
    console.log("Register called for:", email);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists." });
    }

    const otp = generateOtp();
    console.log("Generated OTP:", otp);

    await TempUser.deleteOne({ email });
    const tempUser = new TempUser({
      email,
      otp,
      otpExpiresAt: Date.now() + 60000, // Expires in 2 minutes
    });

    await tempUser.save();
    const emailResponse = await sendOtpEmail(email, otp);
    console.log("Email response:", emailResponse);
    if (emailResponse && !emailResponse.success) {
      return res.status(500).json({ message: emailResponse.error });
    }

    res.status(200).json({ message: "OTP sent to email." });
  } catch (error) {
    console.error("Error registering user:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
// sendOtpMail
const sendOtpEmail = async (email, otp) => {
  // const transporter = nodemailer.createTransport({
  //   host: "smtp.sendgrid.net",
  //   port: 465,
  //   secure: true,
  //   auth: {
  //     user: process.env.EMAIL_USER,
  //     pass: process.env.EMAIL_PASS,
  //   },
  //   tls: {
  //     rejectUnauthorized: false,
  //   },
  // });

  try {
    console.log("email:", email);
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Marine Verification OTP",
      text: `Your OTP for email verification is: ${otp}`,
    };
    console.log("process", process.env.EMAIL_USER);
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
  } catch (error) {
    console.error("Error sending email:", error.message);
    return { success: false, error: "Failed to send OTP email" };
  }
};

// Verify Otp

export const VerifyMail = async (req, res) => {
  try {
    const { email, otp, username, password } = req.body;

    const tempUser = await TempUser.findOne({ email });
    if (!tempUser) {
      return res
        .status(400)
        .json({ message: "Invalid email or user not found." });
    }

    if (String(tempUser.otp).trim() !== String(otp).trim()) {
      return res.status(400).json({ message: "Invalid OTP." });
    }

    if (tempUser.otpExpiresAt < Date.now()) {
      return res.status(400).json({ message: "OTP expired." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      emailVerified: true,
      password: hashedPassword,
    });

    await newUser.save();
    await TempUser.deleteOne({ email });

    res
      .status(200)
      .json({ message: "Email successfully verified. User registered." });
  } catch (error) {
    console.error("Error verifying OTP:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// Login
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    // 1. Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // 2. Verify the password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // 3. Generate access and refresh tokens
    const { RefreshToken, AccessToken } = await generateAccessandRefreshToken(
      user._id
    );

    // 5. Send response with tokens
    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
    };
    return res
      .status(200)
      .cookie("AccessToken", AccessToken, options)
      .cookie("RefreshToken", RefreshToken)
      .json({
        success: true,
        AccessToken: AccessToken,
        user: loggedInUser,
        message: "Login successful",
      });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

//Logout
export const logoutUser = async (req, res) => {
  try {
    // ✅ Clear the authentication cookie
    Object.keys(req.cookies).forEach((cookieName) => {
      res.clearCookie(cookieName, {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "None",
      });
    });
    return res
      .status(200)
      .json({ success: true, message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// user Authorization
export const UserAuthorization = async (req, res) => {
  // console.log("useris Authenticated");
  // console.log(req.user);
  res.json({ message: "Authenticated", user: req.user, authenticated: true });
};
// ForgetPassword
export const initiatePasswordReset = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    // console.log("user", user);
    if (!user) {
      await session.abortTransaction();
      return res.status(400).json({ message: "User not found" });
    }

    // console.log(email);
    const otp = generateOtp();
    await TempUser.findOneAndUpdate(
      { email },
      { otp, otpExpiresAt: Date.now() + 600000 }, // OTP expires in 10 minutes
      { upsert: true, new: true }
    );

    const emailResponse = await sendOtpEmail(email, otp);
    if (emailResponse && !emailResponse.success) {
      await session.abortTransaction();
      return res.status(500).json({ message: emailResponse.error });
    }

    await session.commitTransaction();
    res.status(200).json({ message: "OTP sent to your email" });
  } catch (error) {
    await session.abortTransaction();
    console.error("Error in password reset request", error);
    res.status(500).json({ message: "Internal Server Error" });
  } finally {
    session.endSession();
  }
};

export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    console.log("called:", otp);
    const tempUser = await TempUser.findOne({ email });
    if (
      !tempUser ||
      String(tempUser.otp).trim() !== String(otp).trim() ||
      tempUser.otpExpiresAt < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // OTP is valid, indicate the user can proceed to reset password
    res
      .status(200)
      .json({ message: "OTP verified. You can now reset your password." });
  } catch (error) {
    console.error("Error verifying OTP", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export const updatePasswordAfterOtpVerification = async (req, res) => {
  const { email, newPassword } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Assume OTP was already verified in a previous step
    const tempUser = await TempUser.findOne({ email });
    if (!tempUser) {
      await session.abortTransaction();
      return res.status(400).json({ message: "OTP verification required" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ email }, { password: hashedPassword });

    await TempUser.deleteOne({ email });

    await session.commitTransaction();
    res.status(200).json({ message: "Password successfully updated" });
  } catch (error) {
    await session.abortTransaction();
    console.error("Error resetting password", error);
    res.status(500).json({ message: "Internal Server Error" });
  } finally {
    session.endSession();
  }
};
