import mongoose from "mongoose";
import UserHistory from "../modles/userHistory.js"; // Import the UserHistory model

const addOrUpdateChat = async (req, res) => {
  const { userId, chatId, messages } = req.body;

  console.log(messages);
  console.log(userId);
  console.log(chatId);
  if (!userId || !chatId || !Array.isArray(messages)) {
    return res.status(400).json({
      error: "userId, chatId, and an array of messages are required",
    });
  }

  try {
    // Find or create UserHistory for the user
    let userHistory = await UserHistory.findOne({ user: userId });

    if (!userHistory) {
      // If no UserHistory exists, create a new one
      userHistory = new UserHistory({
        user: userId,
        chats: [],
      });
    }

    // Find the chat by chatId or create a new one if it doesn't exist
    let existingChat = userHistory.chats.find((chat) => chat.id === chatId);
    console.log(existingChat);
    if (existingChat) {
      // If chat exists, append new messages to the chat's messages array
      existingChat.messages.push(...messages);
      existingChat.updatedAt = Date.now(); // Update the chat's updatedAt field
    } else {
      // If chat does not exist, create a new chat object
      const newChat = {
        id: chatId,
        title: `New Chat`,
        messages: messages,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      console.log("newChat:", newChat);
      userHistory.chats.push(newChat);
    }

    // Save the updated or newly created user history
    await userHistory.save();

    res.status(200).json({
      message: existingChat
        ? "Messages added to existing chat"
        : "New chat created",
      chat:
        existingChat || userHistory.chats.find((chat) => chat.id === chatId),
    });
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
    // Find the user's history
    const userHistory = await UserHistory.findOne({ user: userId });

    if (!userHistory) {
      return res
        .status(404)
        .json({ error: "No chat history found for this user" });
    }

    // Extract the titles from the chats
    const titles = userHistory.chats.map((chat) => ({
      id: chat.id,
      title: chat.title,
    }));

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

  if (!userId || !chatId || !newTitle) {
    return res.status(400).json({
      error: "userId, chatId, and newTitle are required",
    });
  }

  try {
    // Find the user's history based on userId
    const userHistory = await UserHistory.findOne({ user: userId });

    if (!userHistory) {
      return res.status(404).json({ error: "User history not found" });
    }

    // Find the chat by chatId
    const chat = userHistory.chats.find((chat) => chat.id === chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Update the title of the chat
    chat.title = newTitle;
    chat.updatedAt = Date.now(); // Update the `updatedAt` timestamp to reflect the change

    // Save the updated user history
    await userHistory.save();

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
    // Find the user's history
    const userHistory = await UserHistory.findOne({ user: userId });

    if (!userHistory) {
      return res
        .status(404)
        .json({ error: "No chat history found for this user" });
    }

    // Find the index of the chat to be deleted
    const chatIndex = userHistory.chats.findIndex((chat) => chat.id === chatId);

    if (chatIndex === -1) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Remove the chat from the chats array
    userHistory.chats.splice(chatIndex, 1);

    // Update the `updatedAt` field to reflect the deletion
    userHistory.updatedAt = Date.now();

    // Save the updated user history with the chat removed
    await userHistory.save();

    res.status(200).json({
      message: "Chat deleted successfully",
      chats: userHistory.chats,
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

  if (!userId || !chatId) {
    return res.status(400).json({ error: "userId and chatId are required" });
  }

  try {
    const userHistory = await UserHistory.findOne({ user: userId });
    if (!userHistory) {
      return res
        .status(404)
        .json({ error: "No chat history found for this user" });
    }

    const chat = userHistory.chats.find((chat) => chat.id === chatId);
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
