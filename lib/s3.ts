import * as s3 from "@aws-cdk/aws-s3";
import {K9AccessCapabilities} from "./k9policy";

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9AccessCapabilities: K9AccessCapabilities
    readonly bucket: s3.Bucket
}