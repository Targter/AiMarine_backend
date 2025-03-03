// import mongoose from "mongoose";
// import jwt from "jsonwebtoken";
// import bcrypt from "bcryptjs";

// const messageSchema = new mongoose.Schema({
//   sender: { type: String, required: true },
//   senderType: { type: String, enum: ["user", "assistant"], required: true }, // Type of sender
//   content: { type: String, required: true },
//   timestamp: { type: Date, default: Date.now },
// });

// // Schema for individual chat titles
// const chatTitleSchema = new mongoose.Schema({
//   title: { type: String, required: true },
//   changedAt: { type: Date, default: Date.now },
// });

// // Schema for individual chats
// const chatSchema = new mongoose.Schema({
//   titles: [chatTitleSchema], // Array of chat titles
//   messages: {
//     type: [messageSchema],
//     validate: {
//       validator: function (messages) {
//         // 🚨 Restrict trial users to only 10 messages per chat
//         const user = this.ownerDocument(); // Get the parent User document
//         if (user.subscriptionType === "trial" && messages.length > 10) {
//           return false;
//         }
//         return true;
//       },
//       message: "Trial users can only have up to 10 messages per chat.",
//     },
//   },
//   createdAt: { type: Date, default: Date.now },
//   updatedAt: { type: Date, default: Date.now },
// });

// // Define User Schema for email-based verification
// const userSchema = new mongoose.Schema({
//   clerkId: { type: String, unique: true }, // Clerk's user ID
//   username: { type: String, lowercase: true },
//   email: { type: String, required: true, unique: true, lowercase: true }, // Email for login
//   otp: { type: String }, // OTP for email verification
//   verified: { type: Boolean, default: false }, // Whether the user is verified
//   emailVerified: { type: Boolean, default: false }, // Email verification flag
//   subscriptionType: {
//     type: String,
//     enum: ["trial", "7-day-premium", "premium"],
//     default: "trial",
//   },
//   usedTrialPremium: { type: Boolean, default: false },
//   subscriptionEndDate: { type: Date },
//   chats: {
//     type: [chatSchema],
//     validate: {
//       validator: function (chats) {
//         // Free tier users can have only one chat
//         if (this.subscriptionType === "trial" && chats.length > 1) {
//           return false;
//         }
//         return true;
//       },
//       message: "Free tier users can only have one chat.",
//     },
//   },
//   createdAt: { type: Date, default: Date.now },
//   refreshToken: {
//     type: String,
//   },
//   password: {
//     type: String,
//   },
//   updatedAt: {
//     type: Date,
//     default: Date.now,
//   },
// });
// //
// userSchema.pre("save", function (next) {
//   if (this.subscriptionType === "trial" && !this.subscriptionEndDate) {
//     this.subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year from now
//   }
//   next();
// });
// // update the subscription type:
// userSchema.methods.updateSubscription = async function (subscriptionType) {
//   try {
//     let subscriptionEndDate;

//     // Calculate subscription end date based on the selected plan
//     if (subscriptionType === "7-day-premium" && this.usedTrialPremium) {
//       subscriptionEndDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now
//       this.usedTrialPremium = true;
//     } else if (subscriptionType === "premium") {
//       subscriptionEndDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days from now
//     } else if (subscriptionType === "premium-yearly") {
//       subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year from now
//       // Trial users should keep their 1-year expiry unless already set
//       if (!this.subscriptionEndDate) {
//         subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year from now
//       }
//     } else {
//       throw new Error("Invalid subscription type");
//     }

//     // Update the user's subscription
//     this.subscriptionType = subscriptionType;
//     this.subscriptionEndDate = subscriptionEndDate;
//     await this.save();

//     return { subscriptionType, subscriptionEndDate };
//   } catch (error) {
//     console.error("Error updating subscription:", error);
//     throw new Error("Subscription update failed");
//   }
// };
// // Middleware to update `updatedAt` field on chat updates
// chatSchema.pre("updateOne", function (next) {
//   this.set({ updatedAt: Date.now() });
//   next();
// });

// // Create User Model
// userSchema.pre("save", async function (next) {
//   if (!this.isModified("password")) {
//     return next();
//   }

//   console.log("Plaintext Password:", this.password); // Log plaintext password
//   this.password = await bcrypt.hash(this.password, 10); // Hash the password
//   console.log("Hashed Password:", this.password); // Log hashed password
//   next();
// });

// userSchema.methods.isPasswordCorrect = async function (password) {
//   console.log("Provided Password:", password); // Log provided password
//   console.log("Stored Hashed Password:", this.password); // Log stored hash
//   const isMatch = await bcrypt.compare(password, this.password);
//   console.log("Password Match:", isMatch); // Log comparison result
//   return isMatch;
// };
// //

// userSchema.methods.GenerateAccessToken = async function () {
//   try {
//     if (!process.env.ACCESS_TOKEN_SECRET || !process.env.ACCESS_TOKEN_EXPIRY) {
//       throw new Error("Access token secret or expiry not configured");
//     }

//     const token = jwt.sign(
//       {
//         id: this._id,
//         email: this.email,
//         username: this.username,
//       },
//       process.env.ACCESS_TOKEN_SECRET,
//       {
//         expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
//       }
//     );

//     console.log("Generated Access Token:", token); // Log generated token
//     return token;
//   } catch (error) {
//     console.error("Error generating access token:", error);
//     throw new Error("Token generation failed");
//   }
// };

// userSchema.methods.GenerateRefreshToken = async function () {
//   try {
//     if (
//       !process.env.REFRESH_TOKEN_SECRET ||
//       !process.env.REFRESH_TOKEN_EXPIRY
//     ) {
//       throw new Error("Refresh token secret or expiry not configured");
//     }

//     const token = jwt.sign(
//       {
//         id: this._id,
//       },
//       process.env.REFRESH_TOKEN_SECRET,
//       {
//         expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
//       }
//     );

//     console.log("Generated Refresh Token:", token); // Log generated token
//     return token;
//   } catch (error) {
//     console.error("Error generating refresh token:", error);
//     throw new Error("Token generation failed");
//   }
// };
// //

// const User = mongoose.model("User", userSchema);
// export default User;
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const messageSchema = new mongoose.Schema({
  id: { type: String },
  content: { type: String, required: true },
  role: { type: String, enum: ["user", "assistant"], required: true },
  timestamp: { type: Number },
  images: [{ type: String }],
});

// Chat schema inside User Schema
const chatSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, required: true },
  messages: {
    type: [messageSchema],
    validate: {
      validator: function (messages) {
        // Trial users can only have a max of 10 messages per chat
        if (
          this.parent().subscriptionType === "trial" &&
          messages.length > 10
        ) {
          return false;
        }
        return true;
      },
      message: "Trial users can only have a maximum of 10 messages per chat.",
    },
  },
  createdAt: { type: Number, required: true },
  updatedAt: { type: Number, required: true },
  expiresAt: {
    type: Date,
    default: function () {
      return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Expires in 30 days
    },
  },
});

// User Schema
const userSchema = new mongoose.Schema({
  clerkId: { type: String, unique: true },
  username: { type: String, lowercase: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  otp: { type: String },
  verified: { type: Boolean, default: false },
  emailVerified: { type: Boolean, default: false },
  subscriptionType: {
    type: String,
    enum: ["trial", "7-day-premium", "premium"],
    default: "trial",
  },
  usedTrialPremium: { type: Boolean, default: false },
  subscriptionEndDate: { type: Date },
  chats: {
    type: [chatSchema],
    validate: {
      validator: function (chats) {
        // Trial users can only have one chat
        if (this.subscriptionType === "trial" && chats.length > 1) {
          return false;
        }
        return true;
      },
      message: "Trial users can only have one chat.",
    },
  },
  createdAt: { type: Date, default: Date.now },
  refreshToken: { type: String },
  password: { type: String },
  updatedAt: { type: Date, default: Date.now },
});

// Automatically delete chats older than 30 days
userSchema.pre("save", function (next) {
  const oneMonthAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  this.chats = this.chats.filter((chat) => chat.createdAt > oneMonthAgo);
  next();
});

// Ensure trial users cannot exceed 10 messages in a chat
userSchema.pre("save", function (next) {
  if (this.subscriptionType === "trial") {
    this.chats.forEach((chat) => {
      chat.messages = chat.messages.slice(-10); // Keep only last 10 messages
    });
  }
  next();
});

// Update updatedAt when messages are added
userSchema.pre("updateOne", function (next) {
  this.set({ updatedAt: Date.now() });
  next();
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Password verification method
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Generate Access Token
userSchema.methods.GenerateAccessToken = function () {
  return jwt.sign(
    { id: this._id, email: this.email, username: this.username },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

// Generate Refresh Token
userSchema.methods.GenerateRefreshToken = function () {
  return jwt.sign({ id: this._id }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  });
};

// Create User Model
const User = mongoose.model("User", userSchema);
export default User;
