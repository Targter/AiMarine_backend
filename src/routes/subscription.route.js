import { Router } from "express";
import {
  updateSubscrition,
  renewSub,
} from "../controllers/subscription.controller.js";

const router = Router();

router.route("/update-subscription").post(updateSubscrition);
router.route("/renewsubscription").post(renewSub);
export default router;
