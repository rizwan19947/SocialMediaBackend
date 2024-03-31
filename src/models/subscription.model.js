import mongoose, { Schema } from 'mongoose';

const subscriptionSchema = new Schema(
    {
        subscriber: {
            type: Schema.Types.ObjectId, // The entity that is subscribing
            ref: 'User',
        },
        channel: {
            type: Schema.Types.ObjectId, // The entity being subscribed to
            ref: 'User',
        },
    },
    { timestamps: true },
);

export const Subscription = mongoose.model('Subscription', subscriptionSchema);
