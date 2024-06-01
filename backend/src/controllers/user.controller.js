import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    console.log(accessToken);
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Internal Server Error", error);
  }
};

const registerUser = asyncHandler(async (req, res, next) => {
  const { username, email, password } = req.body;

  if ([username, email, password].some((field) => field.trim() === "")) {
    throw new ApiError(400, "All fields are required");
  }

  const exitedUser = await User.findOne({ $or: [{ username }, { email }] });

  if (exitedUser) {
    throw new ApiError(400, "User already exists");
  }

  const user = await User.create({ username, email, password });

  if (!user) {
    throw new ApiError(500, "Failed to create user");
  }

  res
    .status(201)
    .json(new ApiResponse(200, registerUser, "User Created Successfully"));
});

const loginUser = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  if ([email, password].some((field) => field.trim() === "")) {
    throw new ApiError(400, "All fields are required");
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, "First Please Create Your Account");
  }

  const isMatch = await user.comparePassword(password);

  if (!isMatch) {
    throw new ApiError(400, "Invalid Username or Password");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  //send cookies

  const options = {
    https: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "Login Successful"
      )
    );
});

const logoutUser = asyncHandler(async (req, res, next) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) throw new ApiError(401, "Unauthorized");
  const user = await User.findOne({ refreshToken });
  if (!user) {
    throw new ApiError(401, "Unauthorized");
  }
  user.refreshToken = null;
  await user.save();
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).json(new ApiResponse(200, null, "Logout Successful"));
});

export { registerUser, loginUser, logoutUser };
