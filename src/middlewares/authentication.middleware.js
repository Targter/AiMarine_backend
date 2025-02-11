import jwt from "jsonwebtoken";
import User from "../modles/useSchema.js";
import ApiError from "../utils/ApiError.js";
import { trycatchhandler } from "../utils/asyncHandler.js";

export const VerifyMiddleWare = trycatchhandler(async (req, res, next) => {
  try {
    console.log("hitting");

    const token =
      req.cookies?.AccessToken ||
      req.header("Authorization")?.replace("Bearer ", "");
    console.log(token);
    if (!token) {
      throw new ApiError(401, "Unauthorized request: No token provided");
    }
    console.log("Token:", token);
    // Corrected to use `let` for `decodedToken`
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (error) {
      console.error("Error verifying token:", error);
      throw new ApiError(401, "Invalid Access Token");
    }

    const user = await User.findById(decodedToken?.id).select(
      "-password -refreshToken"
    );

    if (!user) {
      throw new ApiError(401, "User not found with this token");
    }

    req.user = user; // Attach the user to the request object
    // console.log("User verified:", user);

    // Call the next middleware
    next();
  } catch (error) {
    // Proper error handling
    next(error); // Pass the error to the next middleware
  }
});
