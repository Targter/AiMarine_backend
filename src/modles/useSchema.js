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
        if (this.subscriptionType === "trial" && chats.length > 1) {
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
  if (this.subscriptionType === "trial" && !this.subscriptionEndDate) {
    this.subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year from now
  }
  next();
});

// update the subscription type:
userSchema.methods.updateSubscription = async function (subscriptionType) {
  try {
    let subscriptionEndDate;

    // Calculate subscription end date based on the selected plan
    if (subscriptionType === "7-day-premium") {
      subscriptionEndDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now
    } else if (subscriptionType === "premium") {
      subscriptionEndDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days from now
    } else if (subscriptionType === "trial") {
      // Trial users should keep their 1-year expiry unless already set
      if (!this.subscriptionEndDate) {
        subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year from now
      }
    } else {
      throw new Error("Invalid subscription type");
    }

    // Update the user's subscription
    this.subscriptionType = subscriptionType;
    this.subscriptionEndDate = subscriptionEndDate;
    await this.save();

    return { subscriptionType, subscriptionEndDate };
  } catch (error) {
    console.error("Error updating subscription:", error);
    throw new Error("Subscription update failed");
  }
};

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
