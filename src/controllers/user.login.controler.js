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

//   Register user
export const RegisterUser = async (req, res) => {
  const { email } = req.body;

  // Check if the user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists." });
  }

  // Generate OTP
  const otp = generateOtp();
  console.log("otp", otp);
  // Save OTP with temp user

  await TempUser.deleteOne({ email });
  const tempUser = new TempUser({
    email,
    otp,
    otpExpiresAt: Date.now() + 300000,
  }); // OTP expires in 5 minutes

  await tempUser.save();

  // Send OTP via email (or SMS)
  sendOtpEmail(email, otp); // Implement your own sendOtpEmail function

  res.status(200).json({ message: "OTP sent to email." });
};

// sendOtpMail
const sendOtpEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Email Verification OTP",
    text: `Your OTP for email verification is: ${otp}`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
  } catch (error) {
    console.error("Error sending mail", error);
    throw new Error("Failed to send mail");
  }
};

// Verify Otp

export const VerifyMail = async (req, res) => {
  const { email, otp, username, password } = req.body;

  try {
    // Find the temporary user by email
    const tempUser = await TempUser.findOne({ email });

    if (!tempUser) {
      return res
        .status(400)
        .json({ message: "Invalid email or user not found ." });
    }

    // Check if the OTP matches and is not expired
    console.log("otp:", otp);
    console.log("userotp", tempUser.otp);
    if (String(tempUser.otp).trim() !== String(otp).trim()) {
      return res.status(400).json({ message: "Invalid OTP." });
    }
    console.log("called check");
    if (tempUser.otpExpiresAt < Date.now()) {
      return res.status(400).json({ message: "OTP expired." });
    }

    // Move user to the User collection
    const newUser = new User({
      username: username,
      email: email,
      emailVerified: true,
      password: password, // Consider hashing the password before saving it in production
    });

    await newUser.save();

    // Delete the temp user
    await TempUser.deleteOne({ email });

    // Generate access token
    const { AccessToken, RefreshToken } = await generateAccessandRefreshToken(
      newUser._id
    );
    console.log(AccessToken);

    const loggedInUser = await User.findById(newUser._id).select(
      " -password -refreshToken"
    );

    console.log("loggedInuser:", loggedInUser);

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
        user: loggedInUser,
        message: "Email successfully verified. User registered.",
      });
  } catch (error) {
    console.error("Error verifying OTP", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// Login
export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
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
    // console.log(process.env.ACCESS_TOKEN_SECRET);
    // console.log("Access:", AccessToken);
    // console.log("Refresh:", RefreshToken);
    // 4. Optionally save refresh token to user (if you are using refresh tokens for security)
    // user.refreshToken = RefreshToken;
    // await user.save({ validateBeforeSave: false });

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
  console.log("useris Authenticated");
  res.json({ message: "Authenticated", user: req.user, authenticated: true });
};
// ForgetPassword
export const initiatePasswordReset = async (req, res) => {
  const { email } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
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

    await sendOtpEmail(email, otp);

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
  const { email, otp } = req.body;
  console.log("called:", otp);

  try {
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
