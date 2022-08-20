import * as mongoose from 'mongoose';
import OTP from './IOTP';

import { Document } from 'mongoose';

export default interface OTP extends Document {
    concern: string;
    uniqueId: string;
    otp: number;
    validTill: Date;
}

const otpSchema = new mongoose.Schema(
    {
        concern: {
            required: true,
            type: String
        },
        otp: {
            required: true,
            type: Number
        },
        uniqueId: {
            required: true,
            type: String
        },
        validTill: {
            required: true,
            type: Date
        }
    },
    {
        timestamps: true
    }
);

otpSchema.index(
    {
        createdAt: 1
    },
    {
        expireAfterSeconds: 300
    }
);

export const OtpConcern = mongoose.model<OTP>('otp', otpSchema);
