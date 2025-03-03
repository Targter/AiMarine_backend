import mongoose from "mongoose";
import bcrypt from "bcryptjs";

// Define Temporary User Schema
const tempUserSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true },
  otp: { type: Number },
  otpExpiresAt: { type: Date, required: true }, // OTP expiration time
  createdAt: { type: Date, default: Date.now },
});

// Hash password before saving
// tempUserSchema.pre("save", async function (next) {
//   if (!this.isModified("password")) {
//     return next();
//   }
//   this.password = await bcrypt.hash(this.password, 10);
//   next();
// });

// Export Temporary User Model
const TempUser = mongoose.model("TempUser", tempUserSchema);
export default TempUser;
