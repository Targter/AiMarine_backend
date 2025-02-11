import mongoose from "mongoose";

// Message schema for storing individual messages
const messageSchema = new mongoose.Schema({
  id: { type: String },
  content: { type: String, required: true },
  role: { type: String, enum: ["user", "assistant"], required: true },
  timestamp: { type: Number },
  images: [{ type: String }],
});

// Chat schema for storing individual chats
const chatSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, required: true },
  messages: [messageSchema],
  createdAt: { type: Number, required: true },
  updatedAt: { type: Number, required: true }, // Added updatedAt for each chat
  expiresAt: {
    type: Date,
    required: true,
    default: function () {
      return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days from creation
    },
  },
});

// delete chats
chatSchema.pre("save", function (next) {
  this.expiresAt = new Date(this.createdAt + 30 * 24 * 60 * 60 * 1000); // 30 days from creation
  next();
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

const deleteOldChats = async () => {
  const oneMonthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  try {
    const result = await UserHistory.updateMany(
      {},
      { $pull: { chats: { createdAt: { $lt: oneMonthAgo } } } }
    );
    console.log(`Deleted old chats:`, result);
  } catch (error) {
    console.error("Error deleting old chats:", error);
  }
};

// Run cleanup every 24 hours
setInterval(deleteOldChats, 24 * 60 * 60 * 1000); // Every 24 hours

// Middleware to update `updatedAt` on document update
userHistorySchema.pre("save", function (next) {
  const oneMonthAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  this.chats = this.chats.filter((chat) => chat.createdAt > oneMonthAgo);
  this.updatedAt = Date.now();
  next();
});

// Create UserHistory model
const UserHistory = mongoose.model("UserHistory", userHistorySchema);

export default UserHistory;
