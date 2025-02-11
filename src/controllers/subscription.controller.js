import User from "../modles/useSchema.js";

export const updateSubscrition = async (req, res) => {
  console.log("called");
  const { userId, subscriptionType } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const updatedSubscription = await user.updateSubscription(subscriptionType);
    res.status(200).json(updatedSubscription);
  } catch (error) {
    console.error("Error updating subscription:", error);
    res.status(500).json({ message: "Subscription update failed" });
  }
};

export const renewSub = async (req, res) => {
  const { userId, subscriptionType } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    let subscriptionEndDate;
    const isPremiumUser =
      user.subscriptionType === "premium" ||
      user.subscriptionType === "7-day-premium";
    const isYearlyPremium = user.subscriptionType === "premium-yearly";
    const isSubscriptionActive =
      user.subscriptionEndDate &&
      new Date(user.subscriptionEndDate) > new Date();

    // ⛔ Prevent premium users from switching to `7-day-premium`
    if (isPremiumUser && subscriptionType === "7-day-premium") {
      return res.status(400).json({
        message:
          "You are already a premium user and cannot downgrade to a 7-day premium plan.",
      });
    }

    // ⛔ Prevent yearly premium users from switching to `7-day-premium` or `premium`
    if (
      isYearlyPremium &&
      (subscriptionType === "7-day-premium" || subscriptionType === "premium")
    ) {
      return res.status(400).json({
        message: "Yearly premium users cannot downgrade to a lower plan.",
      });
    }

    // ⛔ Prevent users from downgrading if their current subscription is active
    if (
      isSubscriptionActive &&
      (subscriptionType === "7-day-premium" || subscriptionType === "premium")
    ) {
      return res.status(400).json({
        message: "Your subscription is still active. You cannot downgrade.",
      });
    }

    // ✅ Calculate new subscription end date
    if (subscriptionType === "7-day-premium") {
      subscriptionEndDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    } else if (subscriptionType === "premium") {
      subscriptionEndDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    } else if (subscriptionType === "premium-yearly") {
      subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    } else {
      return res.status(400).json({ message: "Invalid subscription type" });
    }

    // ✅ Update subscription in the database
    user.subscriptionType = subscriptionType;
    user.subscriptionEndDate = subscriptionEndDate;
    await user.save();

    res.status(200).json({ subscriptionType, subscriptionEndDate });
  } catch (error) {
    console.error("Error updating subscription:", error);
    res.status(500).json({ message: "Subscription update failed" });
  }
};
