import User from "../modles/useSchema.js";

export const updateSubscrition = async (req, res) => {
  console.log("called");
  const { userId, subscriptionType } = req.body;
  console.log("userCalling for updating the subscription");
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

    // Calculate new subscription end date
    let subscriptionEndDate;
    if (subscriptionType === "premium") {
      subscriptionEndDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    } else if (subscriptionType === "premium-yearly") {
      subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
    } else {
      return res.status(400).json({ message: "Invalid subscription type" });
    }

    // Update the user's subscription
    user.subscriptionType = subscriptionType;
    user.subscriptionEndDate = subscriptionEndDate;
    await user.save();

    res.status(200).json({ subscriptionType, subscriptionEndDate });
  } catch (error) {
    console.error("Error renewing subscription:", error);
    res.status(500).json({ message: "Subscription renewal failed" });
  }
};
