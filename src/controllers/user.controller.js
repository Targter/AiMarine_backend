import mongoose from "mongoose";
import UserHistory from "../modles/userHistory.js"; // Import the UserHistory model
import User from "../modles/useSchema.js";

const addOrUpdateChat = async (req, res) => {
  const { userId, chatId, messages } = req.body;
  console.log("messagees:", messages);

  console.log("this called");
  if (!userId || !chatId || !Array.isArray(messages)) {
    return res.status(400).json({
      error: "userId, chatId, and an array of messages are required",
    });
  }
  // trial user can no update the chats
  try {
    // Fetch user data to check subscription type
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    console.log("user here");

    let chat = user.chats.find((c) => c.id === chatId);
    // console.log("chatHere:", chat);
    if (!chat) {
      // If chat doesn't exist, create a new one
      if (user.subscriptionType === "trial" && user.chats.length >= 1) {
        throw new Error("Trial users can only have one chat.");
      }

      chat = {
        id: chatId,
        title: "New Chat", // Default title
        messages: [],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };

      user.chats.push(chat);
    }

    // Add new message to the chat
    const validMessages = messages.map((msg) => ({
      role: msg.role,
      content: msg.content,
      images: msg.images,
      _id: new mongoose.Types.ObjectId(), // Ensure unique _id if required
    }));

    chat.messages.push(...validMessages); // Spread messages instead of pushing an array
    chat.updatedAt = Date.now();

    // Limit messages for trial users
    if (user.subscriptionType === "trial") {
      chat.messages = chat.messages.slice(-10);
    }

    await user.save();

    return { success: true, message: "Chat updated successfully", chat };
  } catch (error) {
    console.error("Error handling user history on login:", error);
    res.status(500).json({
      error: "An error occurred while handling user history on login",
    });
  }
};

const fetchUserTitle = async (req, res) => {
  const userId = req.query.userId; // Assuming the user ID is passed as a query parameter

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Restrict chat history access for trial users
    if (user.subscriptionType === "trial") {
      return res.status(403).json({
        error:
          "Trial users cannot access Titles.  Upgrade to premium to access this feature.",
      });
    }

    // Find the user's history
    // const userHistory = await UserHistory.findOne({ user: userId });

    // if (!userHistory) {
    //   return res
    //     .status(404)
    //     .json({ error: "No chat history found for this user" });
    // }

    // Extract the titles from the chats
    const titles = user.chats.map((chat) => ({
      id: chat.id,
      title: chat.title,
    }));

    console.log("user:s:", user);
    res.status(200).json({ titles });
  } catch (error) {
    console.error("Error fetching chat titles:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching chat titles" });
  }
};

const updateChatTitle = async (req, res) => {
  const { userId, chatId, newTitle } = req.body; // Expecting userId, chatId, and the new title
  // 679b266fc7911a053b1c78c3
  console.log("fetchtitleId", userId);
  if (!userId || !chatId || !newTitle) {
    return res.status(400).json({
      error: "userId, chatId, and newTitle are required",
    });
  }
  console.log("userId", userId, chatId, newTitle);
  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the user is a trial user or their subscription has expired
    const isSubscriptionExpired =
      user.subscriptionEndDate &&
      new Date(user.subscriptionEndDate) < new Date();

    if (user.subscriptionType === "trial" || isSubscriptionExpired) {
      return res.status(403).json({
        error:
          "Your subscription does not allow updating chat titles. Upgrade to premium to access this feature.",
      });
    }
    // Find the user's history based on userId
    const chat = user.chats.find((chat) => chat.id === chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Update the chat title
    chat.title = newTitle;
    chat.updatedAt = Date.now();

    // Save updated user data
    await user.save();

    // Respond with the updated chat data
    res.status(200).json({
      message: "Chat title updated successfully",
      chat,
    });
  } catch (error) {
    console.error("Error updating chat title:", error);
    res.status(500).json({
      error: "An error occurred while updating the chat title",
    });
  }
};

const deleteChat = async (req, res) => {
  const { userId, chatId } = req.body;

  if (!userId || !chatId) {
    return res.status(400).json({ error: "userId and chatId are required" });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the user is a trial user or their subscription has expired
    const isSubscriptionExpired =
      user.subscriptionEndDate &&
      new Date(user.subscriptionEndDate) < new Date();

    if (user.subscriptionType === "trial" || isSubscriptionExpired) {
      return res.status(403).json({
        error:
          "Your subscription does not allow deleting chats. Upgrade to premium to access this feature.",
      });
    }
    // Find the user's history
    const chatIndex = user.chats.findIndex((chat) => chat.id === chatId);

    if (chatIndex === -1) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Remove the chat from the chats array
    user.chats.splice(chatIndex, 1);

    // Save updated user data
    await user.save();

    res.status(200).json({
      message: "Chat deleted successfully",
      chats: user.chats,
    });
  } catch (error) {
    console.error("Error deleting chat:", error);
    res
      .status(500)
      .json({ error: "An error occurred while deleting the chat" });
  }
};

const fetchChatHistory = async (req, res) => {
  const { userId } = req.query; // Get the userId from the query parameters
  const { chatId } = req.params; // Get the chatId from the URL params

  console.log("this si useId", userId);
  if (!userId || !chatId) {
    return res.status(400).json({ error: "userId and chatId are required" });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Restrict chat history access for trial users
    if (user.subscriptionType === "trial") {
      return res.status(403).json({
        error:
          "Trial users cannot access chat history. Upgrade to premium to access this feature.",
      });
    }

    const chat = user.chats.find((chat) => chat.id === chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    res.json({ messages: chat.messages });
  } catch (error) {
    console.error("Error fetching chat history:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching the chat history" });
  }
};

export {
  addOrUpdateChat,
  fetchUserTitle,
  updateChatTitle,
  deleteChat,
  fetchChatHistory,
};
