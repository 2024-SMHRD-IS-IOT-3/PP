const express = require("express");
const router = express.Router();
const userRoutes = require("./user");
const analysisRoutes = require("./analysis");
const resultRoutes = require("./result");
const memoRoutes = require("./memo");
const authRoutes = require("./auth");

router.use("/user", userRoutes);
router.use("/analysis", analysisRoutes);

router.use("/", memoRoutes);
router.use("/result", resultRoutes);
router.use("/auth",authRoutes);

router.get("/", async (req, res) => {
  res.sendFile(__dirname + '/test.html');
});

module.exports = router;
