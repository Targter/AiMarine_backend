// import dotenv from "dotenv";
// import app from "./app.js";
// import connectDB from "./db/index2.js";
import dotenv from "dotenv";
// import app from "./app.js";
import app from "./src/app.js";
import connectDB from "./src/db/index2.js";
dotenv.config({
  path: "./.env",
});

connectDB()
  .then(() => {
    app.on("error", (error) => {
      console.log(
        "ERrror: sometimes our express app  will not able to connect thats why it shows an error ",
        error
      );
      // optinally we throwing the error to the global error handler
      throw error;
    });

    app.get("/", (req, res) => {
      res.send("Hello World!");
    });
    app.listen(process.env.PORT || 8080, () => {
      console.log(`server is running at Port : ${process.env.PORT}`);
    });
  })
  .catch((error) => {
    console.log("MONGO DB CONNECTION FAIELD !! ", error);
  });
