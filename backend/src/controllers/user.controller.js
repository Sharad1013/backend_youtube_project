import asyncHandler from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js"
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import ApiResponse from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = await user.generateAccessToken()
        const refreshToken = await user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Error while generating access and refresh token.")
    }
}

export const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists (username, email)
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const { username, email, fullName, password } = req.body
    // console.log(username, " ", email, " ", fullName, " ", password);
    if ([fullName, email, username, password].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        // check for email or username using the $ operator means if email is different but the username should also be unique right.
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    // console.log(avatarLocalPath)
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required")
    }

    // upload images to cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    // console.log(avatar, "on cloudinary")
    // console.log(coverImage, "on cloudinary")

    if (!avatar) {
        throw new ApiError(400, "Avatar is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    // console.log(createdUser)
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user.")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
})

export const loginUser = asyncHandler(async (req, res) => {
    // take the email, password
    // verify email, password is there or not
    // find the user
    // check the password
    // access and refresh token
    // send in cookies

    try {
        const { email, username, password } = req.body
        if (!(username || email)) {
            throw new ApiError(400, "username or email is required")
        }
        if (!password) {
            throw new ApiError(400, "Password is required")
        }

        const user = await User.findOne({
            $or: [{ username }, { email }]
        })

        if (!user) {
            throw new ApiError(404, "User does not exists.")
        }
        const isPasswordValid = await user.isPasswordCorrect(password)

        if (!isPasswordValid) {
            throw new ApiError(401, "Invalid user credentials.")
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)
        const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

        // cookies options
        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax"
        }
        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(200, {
                    user: loggedInUser, accessToken, refreshToken
                }, "User loggedIn Successfully.")
            )

    } catch (error) {
        console.log(error)
        throw new ApiError(500, "Error while logging in.")
    }
})

export const logoutUser = asyncHandler(async (req, res) => {
    try {
        await User.findByIdAndUpdate(
            req.user._id,
            {
                $set: { refreshToken: undefined }
            },
            {
                new: true
            }
        )

        // cookies options
        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax"
        }

        return res.status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json(
                new ApiResponse(200, {}, "User logged out.")
            )

    } catch (error) {
        throw new ApiError(500, "Something went wrong while logging out.")
    }
})

export const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized request.")
        }

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id)

        if (!user) {
            throw new ApiError(401, "Invalid refresh token.")
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh Token is expired or used.")
        }

        // cookies options
        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax"
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshToken(user._id)

        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, "Access token refreshed."))
    } catch (error) {
        console.log(error)
        throw new ApiError(500, "Internal Server Error")
    }
})

export const changeCurrentPassword = asyncHandler(async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body

        if (!(newPassword === confirmPassword)) {
            throw new ApiError(400, "Passwords don't match.")
        }

        const user = await User.findById(req.user?._id)
        const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

        if (!isPasswordCorrect) {
            throw new ApiError(400, "Invalid password.")
        }

        user.password = newPassword
        await user.save({
            validateBeforeSave: false
        })

        return res.status(200)
            .json(new ApiResponse(200, {}, "Password changed successfully."))

    } catch (error) {
        console.log(error)
        throw new ApiError(500, "Internal server error.")
    }
})

export const getCurrentUser = asyncHandler(async (req, res) => {
    try {
        return res.status(200)
            .json(200, req.user, "Current User fetched successfully.")
    } catch (error) {
        throw new ApiError(500, "Internal server error.")
    }
})

export const updateAccountDetails = asyncHandler(async (req, res) => {
    try {

        const { username, email, fullName } = req.body
        if (!fullName || !email || !username) {
            throw new ApiError(400, "All fields are required.")
        }

        const user = await User.findByIdAndUpdate(
            req.user?._id,
            {
                $set: {
                    fullName,
                    email,
                    username
                }
            },
            { new: true }
        ).select("-password")

        return res.status(200)
            .json(new ApiResponse(200, user, "Account details updated successfully."))
    } catch (error) {
        console.log(error)
        throw new ApiError(500, "Internal server error.")
    }
})

// update files
export const updateUserAvatar = asyncHandler(async (req, res) => {
    try {
        const avatarLocalPath = req.file?.path
        if (!avatarLocalPath) {
            throw new ApiError(400, "Avatar file is missing.")
        }

        const avatar = await uploadOnCloudinary(avatarLocalPath)
        if (!avatar.url) {
            throw new ApiError(400, "Error while uploading avatar.")
        }

        const user = await User.findByIdAndUpdate(req.user?._id,
            {
                $set: {
                    avatar: avatar.url
                }
            },
            { new: true }
        ).select("-password")

        return res
            .status(200)
            .json(new ApiResponse(200, user, "User avatar updated successfully."))

    } catch (error) {
        console.log(error)
        throw new ApiError(500, "Internal server error.")
    }
})

export const updateUserCoverImage = asyncHandler(async (req, res) => {
    try {
        const coverImageLocalPath = req.file?.path
        if (!coverImageLocalPath) {
            throw new ApiError(400, "Cover image file is missing.")
        }

        const coverImage = await uploadOnCloudinary(avatarLocalPath)
        if (!coverImage.url) {
            throw new ApiError(400, "Error while uploading cover Image.")
        }

        const user = await User.findByIdAndUpdate(req.user?._id,
            {
                $set: {
                    coverImage: coverImage.url
                }
            },
            { new: true }
        ).select("-password")

        return res
            .status(200)
            .json(new ApiResponse(200, user, "Cover image updated successfully."))

    } catch (error) {
        console.log(error)
        throw new ApiError(500, "Internal server error.")
    }
})