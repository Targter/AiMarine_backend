import User from "../models/User.js";

export const checkSubscription = async (req, res, next) => {
  const user = await User.findById(req.user.id); // Assuming you have user ID from auth middleware

  if (!user) {
    return res.status(401).json({ success: false, message: "User not found" });
  }

  const currentDate = new Date();

  if (user.subscriptionType === "trial") {
    // Check if user has exceeded message limit
    if (user.messageCount >= 7) {
      return res
        .status(403)
        .json({ success: false, message: "Free trial message limit reached" });
    }
  } else if (user.subscriptionType === "7-day-premium") {
    // Check if the 7-day premium has expired
    if (currentDate > user.subscriptionEndDate) {
      return res
        .status(403)
        .json({ success: false, message: "7-day premium expired" });
    }
  } else if (user.subscriptionType === "premium") {
    // Premium users have no restrictions
    if (currentDate > user.subscriptionEndDate) {
      return res
        .status(403)
        .json({ success: false, message: "7-day premium expired" });
    }
    // return next();
  }

  // Increment message count for trial users
  if (user.subscriptionType === "trial") {
    user.messageCount += 1;
    await user.save();
  }

  next();
};
