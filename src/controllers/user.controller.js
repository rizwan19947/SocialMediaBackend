import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

const registerUser = asyncHandler(async (req, res) => {
    /**
     * Intuition:
     *  - Get user details from the frontend/postman based on the defined used model
     *  - validation - not empty
     *  - check if user already exists: check by both username and email
     *  - check for images => check for avatar
     *  - if image/avatar exists, upload to cloudinary
     *  - check if upload on cloudinary was successful
     *  - create user object - create entry in db
     *  - remove password and refresh token field from response (irrelevant data for user)
     *  - check if user created successfully
     *  - return response
     */

    const { fullName, email, username, password } = req.body;

    if ([fullName, email, username, password].some(field => field?.trim() === '')) {
        throw new ApiError(400, 'All fields are compulsory or required!');
    }

    const existingUser = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (existingUser) {
        throw new ApiError(409, 'User with the given email or username already exists!');
    }

    /**
     * Just like how express allows us to have a 'body' prop in request object,
     * multer allows us to have a 'files' prop in the request object
     */
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, 'Avatar file is required!');
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, 'Avatar file is required!');
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || '',
        email,
        password,
        username: username.toLowerCase(),
    });

    const createdUser = await User.findById(user._id).select('-password -refreshToken');

    if (!createdUser) {
        throw new ApiError(500, 'Something went wrong while registering the user!');
    }

    return res.status(201).json(new ApiResponse(200, createdUser, 'User registered successfully!'));
});

const loginUser = asyncHandler(async (req, res) => {
    /**
     * Intuition:
     *  - Get data from req body
     *  - Username or email based
     *  - Find the user in the database
     *  - Password check
     *  - If authenticated provide access and refresh tokens
     *  - Send cookie
     */

    const { email, username, password } = req.body;

    if (!username && !email) {
        throw new ApiError(400, 'Username or password is required!');
    }

    const user = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (!user) {
        throw new ApiError(404, 'User does not exist!');
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, 'Invalid user credentials!');
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).select('-password -refreshToken');

    const cookieOptions = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .cookie('accessToken', accessToken, cookieOptions)
        .cookie('refreshToken', refreshToken, cookieOptions)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                'User logged in Successfully!',
            ),
        );
});

const logoutUser = asyncHandler(async (req, res) => {
    /**
     * Clear cookies
     * Clear refresh token from the database
     */
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined,
            },
        },
        { new: true },
    );

    const cookieOptions = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .clearCookie('accessToken', cookieOptions)
        .clearCookie('refreshToken', cookieOptions)
        .json(new ApiResponse(200, {}, 'User logged out!'));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    /**
     * - Get refresh token from cookies
     * - Decode token and find user using _id in decoded token
     * - If user exists for that refresh token then generate access
     *   and refresh tokens
     */

    /**
     * Structure for accessing cookies may differ when the backend is deployed for multiple platforms
     * for example: web app and mobile app
     */
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, 'Unauthorized Request!');
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id);

        if (!user) {
            throw new ApiError(401, 'Invalid Refresh Token!');
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, 'Refresh token is expired!');
        }

        const cookieOptions = {
            httpOnly: true,
            secure: true,
        };

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id);

        return res
            .status(200)
            .cookie('accessToken', accessToken, cookieOptions)
            .cookie('refreshToken', newRefreshToken, cookieOptions)
            .json(
                new ApiResponse(
                    200,
                    {
                        accessToken,
                        refreshToken: newRefreshToken,
                    },
                    'Access token refreshed!',
                ),
            );
    } catch (error) {
        throw new ApiError(401, error?.message || 'Invalid refresh token!');
    }
});

const generateAccessAndRefreshTokens = async userId => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({
            validateBeforeSave: false,
        });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, 'Something went wrong while generating refresh and access tokens!');
    }
};

const changeCurrentUserPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, 'Invalid old password!');
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, {}, 'Password  changed successfully!'));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user, 'Current user fetched successfully!'));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;

    if (!fullName || !email) {
        throw new ApiError(400, 'All fields are required!');
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email,
            },
        },
        { new: true },
    ).select('-password');

    return res.status(200).json(new ApiResponse(200, user, 'Account details updated successfully!'));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, 'Avatar file is missing!');
    }

    // TODO delete old image - to be done later

    const avatar = uploadOnCloudinary(avatarLocalPath);

    if (!avatar.url) {
        throw new ApiError(400, 'Error while uploading avatar on cloudinary');
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                avatar: avatar.url,
            },
        },
        { new: true },
    ).select('-password');

    return res.status(200).json(new ApiResponse(200, user, 'Avatar updated successfully!'));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if (!coverImageLocalPath) {
        throw new ApiError(400, 'Cover image file is missing!');
    }

    const coverImage = uploadOnCloudinary(coverImageLocalPath);

    if (!coverImage.url) {
        throw new ApiError(400, 'Error while uploading cover image on cloudinary');
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                coverImage: coverImage.url,
            },
        },
        { new: true },
    ).select('-password');

    return res.status(200).json(new ApiResponse(200, user, 'Cover image updated successfully!'));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { username } = req.params;

    if (!username?.trim()) {
        throw new ApiError(400, 'Profile username is missing!');
    }

    const channel = User.aggregate([
        {
            /**
             * Match the user
             */
            $match: {
                username: username?.toLowerCase(),
            },
        },
        {
            /**
             * 1st Pipeline
             * Check the subscribers count for the user
             */
            $lookup: {
                /**
                 * Check from subscription model for the model name
                 * mongodb will turn it completely to lowercase
                 * and add an 's' at the end of the name
                 */
                from: 'subscriptions',
                localField: '_id',
                foreignField: 'channel',
                as: 'subscribers',
            },
        },
        {
            /**
             * 2nd Pipeline
             * Check the user's subscribed to channels
             */
            $lookup: {
                from: 'subscriptions',
                localField: '_id',
                foreignField: 'subscriber',
                as: 'subscribedTo',
            },
        },
        {
            /**
             * 3rd Pipeline
             */
            $addFields: {
                subscribersCount: {
                    $size: '$subscribers',
                },
                channelsSubscribedToCount: {
                    $size: '$subscribedTo',
                },
                isSubscribed: {
                    $cond: {
                        if: { $in: [req.user?._id, '$subscribers.subscriber'] },
                        then: true,
                        else: false,
                    },
                },
            },
        },
        {
            /**
             * 4th Pipeline
             * Limiting the number of fields being returned
             * Getting rid of password, created and updated at and some other
             * unneeded fields
             */
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,
            },
        },
    ]);

    if (!channel?.length) {
        throw new ApiError(404, 'Channel does not exist!');
    }

    return res.status(200).json(new ApiResponse(200, channel[0], 'User channel fetched successfully!'));
});

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id),
            },
        },
        {
            $lookup: {
                /**
                 * Again - Check from subscription model for the model name
                 * mongodb will turn it completely to lowercase
                 * and add an 's' at the end of the name
                 */
                from: 'videos',
                localField: 'watchHistory',
                foreignField: '_id',
                as: 'watchHistory',
                pipeline: [
                    {
                        $lookup: {
                            from: 'users',
                            localField: 'owner',
                            foreignField: '_id',
                            as: 'owner',
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1,
                                    },
                                },
                            ],
                        },
                    },
                    {
                        /**
                         * Just an additional pipeline added
                         * for the ease of frontend devs to resolve the owner array with
                         * an object as a response to simple an object instead
                         * array[ {} ] - No
                         * {} - yes
                         */
                        $addFields: {
                            owner: {
                                $first: '$owner',
                            },
                        },
                    },
                ],
            },
        },
    ]);

    return res.status(200).json(new ApiResponse(200, user[0].watchHistory, 'Watch history fetched successfully!'));
});

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentUserPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
};