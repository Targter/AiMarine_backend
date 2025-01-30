import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  senderType: { type: String, enum: ["user", "assistant"], required: true }, // Type of sender
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

// Schema for individual chat titles
const chatTitleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  changedAt: { type: Date, default: Date.now },
});

// Schema for individual chats
const chatSchema = new mongoose.Schema({
  titles: [chatTitleSchema], // Array of chat titles
  messages: [messageSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Define User Schema for email-based verification
const userSchema = new mongoose.Schema({
  username: { type: String, lowercase: true },
  email: { type: String, required: true, unique: true, lowercase: true }, // Email for login
  otp: { type: String }, // OTP for email verification
  verified: { type: Boolean, default: false }, // Whether the user is verified
  emailVerified: { type: Boolean, default: false }, // Email verification flag
  subscriptionType: {
    type: String,
    enum: ["trial", "7-day-premium", "premium"],
    default: "trial",
  },
  subscriptionEndDate: { type: Date },
  chats: {
    type: [chatSchema],
    validate: {
      validator: function (chats) {
        // Free tier users can have only one chat
        if (this.subscriptionType === "free" && chats.length > 1) {
          return false;
        }
        return true;
      },
      message: "Free tier users can only have one chat.",
    },
  },
  createdAt: { type: Date, default: Date.now },
  refreshToken: {
    type: String,
  },
  password: {
    type: String,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

//
userSchema.pre("save", function (next) {
  if (this.subscriptionType === "free" && this.chats.length > 1) {
    this.chats = this.chats.slice(0, 1); // Retain only the first chat
  }
  next();
});

// Middleware to update `updatedAt` field on chat updates
chatSchema.pre("updateOne", function (next) {
  this.set({ updatedAt: Date.now() });
  next();
});

// Create User Model
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
  // console.log("isPasswordiscalling")
};

//

userSchema.methods.GenerateAccessToken = async function () {
  try {
    return await jwt.sign(
      {
        id: this._id,
        email: this.email,
        username: this.username,
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
      }
    );
  } catch (error) {
    console.error("Error generating access token:", error);
    throw new Error("Token generation failed");
  }
};

userSchema.methods.GenerateRefreshToken = async function () {
  return await jwt.sign(
    {
      id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

//

const User = mongoose.model("User", userSchema);
export default User;
