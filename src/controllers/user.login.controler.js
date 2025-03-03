// import mongoose from "mongoose";
// import TempUser from "../modles/Tempuser.moddles.js";
// import bcrypt from "bcryptjs";
// import User from "../modles/useSchema.js";
// import nodemailer from "nodemailer";

//   // Generate access and refresh token
//   const generateAccessandRefreshToken = async (UserId) => {
//     try {
//       const user = await User.findById(UserId);
//       const AccessToken = await user.GenerateAccessToken();
//       const RefreshToken = await user.GenerateRefreshToken();
//       // giving the value of refreshToken
//       user.refreshToken = RefreshToken;

//       // it save this to our database  require the password to do this thats why we done this
//       await user.save({ validateBeforeSave: false });

//       return { AccessToken, RefreshToken };
//     } catch (error) {
//       throw new ApiError(
//         500,
//         "Something went wrong while generating the access and refresh Token"
//       );
//     }
//   };
//   // Generate a 6-digit OTP
//   const generateOtp = () => {
//     return Math.floor(100000 + Math.random() * 900000).toString();
//   };

//   // export default generateOtp;
//   const transporter = nodemailer.createTransport({
//     host: "smtp.gmail.com",
//     port: 465,
//     // secure: true,
//     auth: {
//       user: process.env.EMAIL_USER,
//       pass: process.env.EMAIL_PASS,
//     },
//     tls: {
//       rejectUnauthorized: false,
//     },
//     // console.log("process",process.env.EMAIL_USER);
//   });
//   //   Register user
//   export const RegisterUser = async (req, res) => {
//     try {
//       const { email } = req.body;
//       console.log("Register called for:", email);

//       const existingUser = await User.findOne({ email });
//       if (existingUser) {
//         return res.status(400).json({ message: "User already exists." });
//       }

//       const otp = generateOtp();
//       console.log("Generated OTP:", otp);

//       await TempUser.deleteOne({ email });
//       const tempUser = new TempUser({
//         email,
//         otp,
//         otpExpiresAt: Date.now() + 120000, // Expires in 2 minutes
//       });

//       await tempUser.save();
//       await sendOtpEmail(email, otp);
//       // console.log("Email response:", emailResponse);
//       // if (emailResponse && !emailResponse.success) {
//       //   return res.status(500).json({ message: emailResponse.error });
//       // }

//       res.status(200).json({ message: "OTP sent to email." });
//     } catch (error) {
//       console.error("Error registering user:", error.message);
//       res.status(500).json({ message: "Internal Server Error" });
//     }
//   };
//   // sendOtpMail
//   const sendOtpEmail = async (email, otp) => {
//     try {
//       console.log("email:", email);
//       const mailOptions = {
//         from: process.env.EMAIL_USER,
//         to: email,
//         subject: "Marine Verification OTP",
//         text: `Your OTP for email verification is: ${otp}`,
//       };
//       // console.log("process", process.env.EMAIL_USER);
//       await transporter.sendMail(mailOptions);
//       // console.log("Email sent:", info.response);
//     } catch (error) {
//       console.error("Error sending email:", error.message);
//       return { success: false, error: "Failed to send OTP email" };
//     }
//   };

//   // Verify Otp
//   export const VerifyMail = async (req, res) => {
//     try {
//       const { email, otp, username, password } = req.body;

//       // 1. Find the TempUser
//       const tempUser = await TempUser.findOne({ email });
//       if (!tempUser) {
//         return res.status(400).json({ message: "Invalid email or OTP expired." });
//       }

//       // 2. Verify OTP
//       if (String(tempUser.otp).trim() !== String(otp).trim()) {
//         return res.status(400).json({ message: "Invalid OTP." });
//       }

//       // 3. Check if OTP has expired
//       if (tempUser.otpExpiresAt < Date.now()) {
//         return res.status(400).json({ message: "OTP expired." });
//       }

//       // 5. Create a new User
//       const newUser = new User({
//         username,
//         email,
//         emailVerified: true,
//         password: password,
//       });

//       // 6. Save the new user to the database
//       await newUser.save();

//       // 7. Generate access and refresh tokens
//       const AccessToken = await newUser.GenerateAccessToken();
//       const RefreshToken = await newUser.GenerateRefreshToken();

//       // 8. Save the refresh token to the database
//       newUser.refreshToken = RefreshToken;
//       await newUser.save({ validateBeforeSave: false });

//       // 9. Delete the TempUser
//       await TempUser.deleteOne({ email });

//       // 10. Send response with tokens and user data
//       const options = {
//         httpOnly: true,
//         secure: process.env.NODE_ENV === "production", // Set to false in development
//         sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
//         maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//       };

//       return res
//         .status(200)
//         .cookie("AccessToken", AccessToken, options)
//         .cookie("RefreshToken", RefreshToken, options)
//         .json({
//           success: true,
//           AccessToken,
//           user: newUser,
//           message: "Email verified. User registered.",
//         });
//     } catch (error) {
//       console.error("Error verifying OTP:", error.message);
//       res.status(500).json({ message: "Internal Server Error" });
//     }
//   };

//   // Login
//   export const loginUser = async (req, res) => {
//     try {
//       const { email, password } = req.body;

//       // 1. Check if user exists
//       const user = await User.findOne({ email });
//       if (!user) {
//         return res.status(400).json({ message: "Invalid email or password." });
//       }

//       // 2. Verify the password
//       const isMatch = await user.isPasswordCorrect(password);
//       if (!isMatch) {
//         return res.status(400).json({ message: "Invalid email or password." });
//       }

//       // 3. Generate access and refresh tokens
//       const AccessToken = await user.GenerateAccessToken();
//       const RefreshToken = await user.GenerateRefreshToken();

//       // 4. Save the refresh token to the database
//       user.refreshToken = RefreshToken;
//       await user.save({ validateBeforeSave: false });

//       // 5. Remove sensitive fields from the user object
//       const loggedInUser = await User.findById(user._id).select(
//         "-password -refreshToken"
//       );

//       // 6. Set cookie options
//       // const options = {
//       //   httpOnly: true,
//       //   secure: process.env.NODE_ENV === "production", // Set to false in development
//       //   sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
//       //   maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//       // };

//       // // 7. Send response with tokens and user data

//       // res.setHeader("Access-Control-Allow-Origin", "http://localhost:5173"); // Replace with your frontend URL
//       // res.setHeader("Access-Control-Allow-Credentials", "true");
//       // res.setHeader("Set-Cookie", [
//       //   `AccessToken=${AccessToken}; HttpOnly; Secure;  Max-Age=${options.maxAge}; Path=/`,
//       //   `RefreshToken=${RefreshToken}; HttpOnly; Secure; SameSite=None; Max-Age=${options.maxAge}; Path=/`,
//       // ]);

//       // res.cookie("AccessToken", AccessToken, {
//       //   httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
//       //   secure: true, // Only send over HTTPS
//       //   sameSite: "none", // Required for cross-origin requests
//       //   domain: ".vercel.app", // Use the parent domain
//       //   maxAge: 1000 * 60 * 60 * 24, // 1 day
//       // });
//       // res.cookie("RefreshToken", RefreshToken, options);

//       // // 9. Return response
//       // return res.status(200).json({
//       //   AccessToken: AccessToken,
//       //   success: true,
//       //   user: loggedInUser,
//       //   message: "Login successful",
//       // });
//       // another
//       // const options = {
//       //   httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
//       //   secure: true, // Only send over HTTPS
//       //   sameSite: "none", // Required for cross-origin requests
//       //   domain: ".vercel.app", // Use the parent domain
//       //   maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//       //   path: "/", // Cookie is accessible across the entire domain
//       // };

//       // res.cookie("AccessToken", AccessToken, options);
//       // res.cookie("RefreshToken", RefreshToken, options);

//       // // 8. Return response
//       // return res.status(200).json({
//       //   AccessToken: AccessToken,
//       //   success: true,
//       //   user: loggedInUser,
//       //   message: "Login successful",
//       // });
//       // new
//       // res.setHeader(
//       //   "Access-Control-Allow-Origin",
//       //   "https://abmarineai.vercel.app"
//       // ); // Replace with your frontend URL
//       // res.setHeader("Access-Control-Allow-Credentials", "true");
//       // res.setHeader("Set-Cookie", [
//       //   `AccessToken=${AccessToken}; HttpOnly; Secure; SameSite=None; Max-Age=${
//       //     7 * 24 * 60 * 60
//       //   }; Path=/; Domain=https://abmarineai.vercel.app`,
//       //   `RefreshToken=${RefreshToken}; HttpOnly; Secure; SameSite=None; Max-Age=${
//       //     7 * 24 * 60 * 60
//       //   }; Path=/; Domain=https://abmarineai.vercel.app`,
//       // ]);
//       // return res.status(200).cookie("AccessToken", AccessToken, options).json({
//       //   AccessToken: AccessToken,
//       //   success: true,
//       //   user: loggedInUser,
//       //   message: "Login successful",
//       // });

//       // //////////////////////////////////
//       const cookieOptions = {
//         httpOnly: true,
//         secure: true, // Must be true in production for Vercel (HTTPS)
//         sameSite: "None", // Required for cross-origin cookies
//         path: "/",
//         maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
//         domain: ".vercel.app", // Adjust to your custom domain if applicable
//       };

//       // 7. Set cookies using res.cookie()
//       res.cookie("AccessToken", AccessToken, cookieOptions);
//       res.cookie("RefreshToken", RefreshToken, cookieOptions);

//       // 8. Return response
//       return res.status(200).json({
//         success: true,
//         AccessToken, // Optional: Send token in response if frontend needs it
//         user: loggedInUser,
//         message: "Login successful",
//       });
//     } catch (error) {
//       console.error("Error during login:", error);
//       res.status(500).json({ message: "Internal Server Error" });
//     }
//   };

// //Logout
// export const logoutUser = async (req, res) => {
//   try {
//     // ✅ Clear the authentication cookie
//     Object.keys(req.cookies).forEach((cookieName) => {
//       res.clearCookie(cookieName, {
//         path: "/",
//         httpOnly: true,
//         secure: true,
//         sameSite: "None",
//       });
//     });
//     return res
//       .status(200)
//       .json({ success: true, message: "Logout successful" });
//   } catch (error) {
//     console.error("Logout error:", error);
//     return res
//       .status(500)
//       .json({ success: false, message: "Internal server error" });
//   }
// };

// // user Authorization
// import { clerkClient } from "@clerk/clerk-sdk-node";
// import User from "../modles/useSchema.js";
export const UserAuthorization = async (req, res) => {
  if (!req.auth?.userId) {
    return res.status(401).json({ message: "User not authenticated" });
  }

  try {
    console.log(req.auth.userId);
    const userId = req.auth.userId;
    // const user = await clerkClient.users.getUser(req.auth.userId);
    // console.log(user);
    const user = await User.findOne({ clerkId: userId });
    console.log(user);
    if (!user) {
      return res.status(404).json({ message: "Please Login Again" });
    }
    res.json({
      message: "Authenticated",
      user,
      authenticated: true,
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ message: "Failed to fetch user details" });
  }
};

// // ForgetPassword
// export const initiatePasswordReset = async (req, res) => {
//   const session = await mongoose.startSession();
//   session.startTransaction();

//   try {
//     const { email } = req.body;
//     const user = await User.findOne({ email });
//     // console.log("user", user);
//     if (!user) {
//       await session.abortTransaction();
//       return res.status(400).json({ message: "User not found" });
//     }

//     // console.log(email);
//     const otp = generateOtp();
//     await TempUser.findOneAndUpdate(
//       { email },
//       { otp, otpExpiresAt: Date.now() + 600000 }, // OTP expires in 10 minutes
//       { upsert: true, new: true }
//     );

//     const emailResponse = await sendOtpEmail(email, otp);
//     if (emailResponse && !emailResponse.success) {
//       await session.abortTransaction();
//       return res.status(500).json({ message: emailResponse.error });
//     }

//     await session.commitTransaction();
//     res.status(200).json({ message: "OTP sent to your email" });
//   } catch (error) {
//     await session.abortTransaction();
//     console.error("Error in password reset request", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   } finally {
//     session.endSession();
//   }
// };

// export const verifyOtp = async (req, res) => {
//   try {
//     const { email, otp } = req.body;
//     console.log("called:", otp);
//     const tempUser = await TempUser.findOne({ email });
//     if (
//       !tempUser ||
//       String(tempUser.otp).trim() !== String(otp).trim() ||
//       tempUser.otpExpiresAt < Date.now()
//     ) {
//       return res.status(400).json({ message: "Invalid or expired OTP" });
//     }

//     // OTP is valid, indicate the user can proceed to reset password
//     res
//       .status(200)
//       .json({ message: "OTP verified. You can now reset your password." });
//   } catch (error) {
//     console.error("Error verifying OTP", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// };

// export const updatePasswordAfterOtpVerification = async (req, res) => {
//   const { email, newPassword } = req.body;
//   const session = await mongoose.startSession();
//   session.startTransaction();

//   try {
//     // Assume OTP was already verified in a previous step
//     const tempUser = await TempUser.findOne({ email });
//     if (!tempUser) {
//       await session.abortTransaction();
//       return res.status(400).json({ message: "OTP verification required" });
//     }

//     const hashedPassword = await bcrypt.hash(newPassword, 10);
//     await User.findOneAndUpdate({ email }, { password: hashedPassword });

//     await TempUser.deleteOne({ email });

//     await session.commitTransaction();
//     res.status(200).json({ message: "Password successfully updated" });
//   } catch (error) {
//     await session.abortTransaction();
//     console.error("Error resetting password", error);
//     res.status(500).json({ message: "Internal Server Error" });
//   } finally {
//     session.endSession();
//   }
// };

import { Webhook } from "svix"; // For verifying Clerk Webhooks
// import User from "../models/User.js"; // Your Mongoose User model
import User from "../modles/useSchema.js";

// Clerk Webhook Secret (store in .env)
const CLERK_WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET;

/**
 * Handle Clerk Webhooks for user creation/updation.
 */
export const handleClerkWebhook = async (req, res) => {
  try {
    console.log("this called......");
    const payload = req.body;
    const headers = req.headers;

    // Verify Clerk Webhook
    const wh = new Webhook(CLERK_WEBHOOK_SECRET);
    const event = wh.verify(JSON.stringify(payload), headers);

    console.log("Clerk Webhook Event:", event);

    const { id, email_addresses, first_name, last_name } = event.data;

    if (event.type === "user.created" || event.type === "user.updated") {
      const email = email_addresses[0]?.email_address;

      // Check if user exists in DB
      let user = await User.findOne({ email });

      if (!user) {
        // Create a new user
        user = new User({
          clerkId: id, // Store Clerk's user ID
          username: first_name || last_name || "User",
          email,
          emailVerified: true, // Since Clerk handles verification
        });

        await user.save();
        console.log("New User Created:", user);
      } else {
        // Update existing user
        user.clerkId = id;
        user.emailVerified = true;
        await user.save();
        console.log("User Updated:", user);
      }
    }

    res
      .status(200)
      .json({ success: true, message: "User synced with database" });
  } catch (error) {
    console.error("Error handling Clerk webhook:", error);
    res
      .status(500)
      .json({ success: false, message: "Webhook handling failed" });
  }
};
