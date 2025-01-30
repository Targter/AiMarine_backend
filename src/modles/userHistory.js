import mongoose from "mongoose";

// Message schema for storing individual messages
const messageSchema = new mongoose.Schema({
  id: { type: String },
  content: { type: String, required: true },
  role: { type: String, enum: ["user", "assistant"], required: true },
  timestamp: { type: Number },
});

// Chat schema for storing individual chats
const chatSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, required: true },
  messages: [messageSchema],
  createdAt: { type: Number, required: true },
  updatedAt: { type: Number, required: true }, // Added updatedAt for each chat
});

// User history schema to store multiple chats for each user
const userHistorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true, // Ensure user is defined
  },
  chats: [chatSchema], // Allow multiple chats
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Middleware to update `updatedAt` on document update
userHistorySchema.pre("save", function (next) {
  this.updatedAt = Date.now();
  next();
});

// Create UserHistory model
const UserHistory = mongoose.model("UserHistory", userHistorySchema);

export default UserHistory;
