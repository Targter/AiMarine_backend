import { Router } from "express";
import {
  addOrUpdateChat,
  deleteChat,
  fetchChatHistory,
  fetchUserTitle,
  updateChatTitle,
} from "../controllers/user.controller.js";
import { VerifyMiddleWare } from "../middlewares/authentication.middleware.js";
const router = Router();

router.route("/updateData").post(VerifyMiddleWare, addOrUpdateChat);
router.route("/titles").get(VerifyMiddleWare, fetchUserTitle);
router.route("/updateChatTitle").put(VerifyMiddleWare, updateChatTitle);
router.route("/deleteChat").delete(VerifyMiddleWare, deleteChat);
router.route("/chatHistory/:chatId").get(VerifyMiddleWare, fetchChatHistory);
export default router;
