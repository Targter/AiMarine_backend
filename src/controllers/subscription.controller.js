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

// export const renewSub = async (req, res) => {
//   const { userId, subscriptionType } = req.body;
//   console.log("this ccalled subscripotion");

//   try {
//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     let subscriptionEndDate;
//     const isPremiumUser =
//       user.subscriptionType === "premium" ||
//       user.subscriptionType === "7-day-premium";
//     const isYearlyPremium = user.subscriptionType === "premium-yearly";
//     const isSubscriptionActive =
//       user.subscriptionEndDate &&
//       new Date(user.subscriptionEndDate) > new Date();

//     // Define subscription hierarchy ranks
//     const subscriptionRanks = {
//       "premium-yearly": 3,
//       premium: 2,
//       "7-day-premium": 1,
//       trial: 0,
//       none: 0,
//     };

//     const currentRank = subscriptionRanks[user.subscriptionType] || 0;
//     const newRank = subscriptionRanks[subscriptionType] || 0;

//     // ⛔ Prevent premium users from switching to `7-day-premium`
//     if (isPremiumUser && subscriptionType === "7-day-premium") {
//       return res.status(400).json({
//         message:
//           "You are already a premium user and cannot downgrade to a 7-day premium plan.",
//       });
//     }

//     // ⛔ Prevent yearly premium users from switching to lower plans
//     if (
//       isYearlyPremium &&
//       (subscriptionType === "7-day-premium" || subscriptionType === "premium")
//     ) {
//       return res.status(400).json({
//         message: "Yearly premium users cannot downgrade to a lower plan.",
//       });
//     }

//     // ⛔ Prevent downgrades if current subscription is active
//     if (isSubscriptionActive && newRank < currentRank) {
//       return res.status(400).json({
//         message: "Your subscription is still active. You cannot downgrade.",
//       });
//     }

//     // ✅ Calculate new subscription end date
//     switch (subscriptionType) {
//       case "7-day-premium":
//         subscriptionEndDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
//         break;
//       case "premium":
//         subscriptionEndDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
//         break;
//       case "premium-yearly":
//         subscriptionEndDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
//         break;
//       default:
//         return res.status(400).json({ message: "Invalid subscription type" });
//     }

//     // ✅ Update subscription in the database
//     user.subscriptionType = subscriptionType;
//     user.subscriptionEndDate = subscriptionEndDate;
//     await user.save();

//     res.status(200).json({ subscriptionType, subscriptionEndDate });
//   } catch (error) {
//     console.error("Error updating subscription:", error);
//     res.status(500).json({ message: "Subscription update failed" });
//   }
// };
export const renewSub = async (req, res) => {
  const { userId, subscriptionType } = req.body;
  console.log("Subscription renewal called");

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const now = new Date();
    const isSubscriptionActive =
      user.subscriptionEndDate && new Date(user.subscriptionEndDate) > now;

    // Define subscription ranks (higher value = higher plan)
    const subscriptionRanks = {
      "premium-yearly": 3,
      premium: 2,
      "7-day-premium": 1,
      trial: 0,
      none: 0,
    };

    const currentRank = subscriptionRanks[user.subscriptionType] || 0;
    const newRank = subscriptionRanks[subscriptionType] || 0;

    // Prevent premium users from downgrading to trial or 7-day premium
    if (
      user.subscriptionType === "premium" &&
      ["7-day-premium", "trial"].includes(subscriptionType)
    ) {
      return res.status(400).json({
        message: "Premium users cannot downgrade to trial or 7-day premium.",
      });
    }

    // Prevent yearly premium users from downgrading
    if (user.subscriptionType === "premium-yearly" && newRank < currentRank) {
      return res.status(400).json({
        message: "Yearly premium users cannot downgrade their plan.",
      });
    }

    // Prevent downgrades while subscription is active
    if (isSubscriptionActive && newRank < currentRank) {
      return res.status(400).json({
        message: "Your subscription is still active. You cannot downgrade.",
      });
    }

    // Prevent users from taking 7-day premium twice
    if (subscriptionType === "7-day-premium" && user.usedTrialPremium) {
      return res.status(400).json({
        message: "You can only use the 7-day premium once in a lifetime.",
      });
    }

    // Calculate new subscription end date
    let subscriptionEndDate;
    switch (subscriptionType) {
      case "7-day-premium":
        subscriptionEndDate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        user.usedTrialPremium = true;
        break;
      case "premium":
        // If the user is already on premium, extend the subscription instead of overriding
        subscriptionEndDate = isSubscriptionActive
          ? new Date(
              user.subscriptionEndDate.getTime() + 30 * 24 * 60 * 60 * 1000
            )
          : new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        break;
      case "premium-yearly":
        subscriptionEndDate = new Date(
          now.getTime() + 365 * 24 * 60 * 60 * 1000
        );
        break;
      default:
        return res.status(400).json({ message: "Invalid subscription type" });
    }

    // Update subscription
    user.subscriptionType = subscriptionType;
    user.subscriptionEndDate = subscriptionEndDate;
    await user.save();

    res.status(200).json({ subscriptionType, subscriptionEndDate });
  } catch (error) {
    console.error("Error updating subscription:", error);
    res.status(500).json({ message: "Subscription update failed" });
  }
};
