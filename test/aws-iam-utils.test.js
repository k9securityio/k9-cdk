"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const aws_iam_1 = require("@aws-cdk/aws-iam");
const aws_iam_utils_1 = require("../lib/aws-iam-utils");
test('getAllowedPrincipalArns should return empty when Policy has no statements', () => {
    expect(aws_iam_utils_1.getAllowedPrincipalArns(new aws_iam_1.PolicyDocument())).toEqual(new Set());
});
test('getAllowedPrincipalArns should return principal for Allow Statement with one Principal', () => {
    const expectPrincipal = "arn:aws:iam::123456789012:role/Some-CustomS3AutoDeleteObject-Role";
    const policyStatement = aws_iam_1.PolicyStatement.fromJson({
        "Effect": "Allow",
        "Principal": {
            "AWS": expectPrincipal
        },
        "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*", "s3:DeleteObject*"],
        "Resource": [
            "arn:aws:s3:::a-bucket",
            "arn:aws:s3:::a-bucket/*"
        ]
    });
    const policyDocument = new aws_iam_1.PolicyDocument();
    policyDocument.addStatements(policyStatement);
    expect(aws_iam_utils_1.getAllowedPrincipalArns(policyDocument)).toEqual(new Set([expectPrincipal]));
});
test('getAllowedPrincipalArns should return principals for Allow Statement with multiple Principals', () => {
    const expectPrincipal = [
        "arn:aws:iam::123456789012:role/Some-CustomS3AutoDeleteObject-Role",
        "${Token[TOKEN.55]}"
    ];
    const policyStatement = aws_iam_1.PolicyStatement.fromJson({
        "Effect": "Allow",
        "Principal": {
            "AWS": expectPrincipal
        },
        "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*", "s3:DeleteObject*"],
        "Resource": [
            "arn:aws:s3:::a-bucket",
            "arn:aws:s3:::a-bucket/*"
        ]
    });
    const policyDocument = new aws_iam_1.PolicyDocument();
    policyDocument.addStatements(policyStatement);
    expect(aws_iam_utils_1.getAllowedPrincipalArns(policyDocument)).toEqual(new Set(expectPrincipal));
});
test('getAllowedPrincipalArns should skip principals for Allow Statement when Conditions exist', () => {
    const principalElementsToTest = [
        "*",
        [
            "arn:aws:iam::123456789012:role/Some-CustomS3AutoDeleteObject-Role",
            "${Token[TOKEN.55]}"
        ]
    ];
    for (let principal of principalElementsToTest) {
        const policyStatement = aws_iam_1.PolicyStatement.fromJson({
            "Effect": "Allow",
            "Principal": {
                "AWS": principal
            },
            "Action": ["s3:GetObject"],
            "Resource": [
                "arn:aws:s3:::a-bucket",
                "arn:aws:s3:::a-bucket/*"
            ],
            "Condition": {
                "ArnEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::123456789012:user/ci",
                        "arn:aws:sts::139710491120:federated-user/admin",
                        "arn:aws:iam::012345678901:role/external-auditor",
                    ]
                }
            }
        });
        const policyDocument = new aws_iam_1.PolicyDocument();
        policyDocument.addStatements(policyStatement);
        expect(aws_iam_utils_1.getAllowedPrincipalArns(policyDocument)).toEqual(new Set());
    }
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXdzLWlhbS11dGlscy50ZXN0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiYXdzLWlhbS11dGlscy50ZXN0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsOENBQWlFO0FBQ2pFLHdEQUE2RDtBQUU3RCxJQUFJLENBQUMsMkVBQTJFLEVBQUUsR0FBRyxFQUFFO0lBQ25GLE1BQU0sQ0FBQyx1Q0FBdUIsQ0FBQyxJQUFJLHdCQUFjLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksR0FBRyxFQUFVLENBQUMsQ0FBQztBQUNyRixDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyx3RkFBd0YsRUFBRSxHQUFHLEVBQUU7SUFDaEcsTUFBTSxlQUFlLEdBQUcsbUVBQW1FLENBQUM7SUFDNUYsTUFBTSxlQUFlLEdBQUcseUJBQWUsQ0FBQyxRQUFRLENBQUM7UUFDckMsUUFBUSxFQUFFLE9BQU87UUFDakIsV0FBVyxFQUFFO1lBQ1QsS0FBSyxFQUFFLGVBQWU7U0FDekI7UUFDRCxRQUFRLEVBQUUsQ0FBQyxlQUFlLEVBQUUsZUFBZSxFQUFFLFVBQVUsRUFBRSxrQkFBa0IsQ0FBQztRQUM1RSxVQUFVLEVBQUU7WUFDUix1QkFBdUI7WUFDdkIseUJBQXlCO1NBQzVCO0tBQ0osQ0FBQyxDQUFDO0lBQ1gsTUFBTSxjQUFjLEdBQUcsSUFBSSx3QkFBYyxFQUFFLENBQUM7SUFDNUMsY0FBYyxDQUFDLGFBQWEsQ0FBQyxlQUFlLENBQUMsQ0FBQztJQUM5QyxNQUFNLENBQUMsdUNBQXVCLENBQUMsY0FBYyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxHQUFHLENBQVMsQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDaEcsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsK0ZBQStGLEVBQUUsR0FBRyxFQUFFO0lBQ3ZHLE1BQU0sZUFBZSxHQUFHO1FBQ3BCLG1FQUFtRTtRQUNuRSxvQkFBb0I7S0FDbkIsQ0FBQztJQUNOLE1BQU0sZUFBZSxHQUFHLHlCQUFlLENBQUMsUUFBUSxDQUFDO1FBQ3JDLFFBQVEsRUFBRSxPQUFPO1FBQ2pCLFdBQVcsRUFBRTtZQUNULEtBQUssRUFBRSxlQUFlO1NBQ3pCO1FBQ0QsUUFBUSxFQUFFLENBQUMsZUFBZSxFQUFFLGVBQWUsRUFBRSxVQUFVLEVBQUUsa0JBQWtCLENBQUM7UUFDNUUsVUFBVSxFQUFFO1lBQ1IsdUJBQXVCO1lBQ3ZCLHlCQUF5QjtTQUM1QjtLQUNKLENBQUMsQ0FBQztJQUNYLE1BQU0sY0FBYyxHQUFHLElBQUksd0JBQWMsRUFBRSxDQUFDO0lBQzVDLGNBQWMsQ0FBQyxhQUFhLENBQUMsZUFBZSxDQUFDLENBQUM7SUFDOUMsTUFBTSxDQUFDLHVDQUF1QixDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksR0FBRyxDQUFTLGVBQWUsQ0FBQyxDQUFDLENBQUM7QUFDOUYsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsMEZBQTBGLEVBQUUsR0FBRyxFQUFFO0lBQ2xHLE1BQU0sdUJBQXVCLEdBQUc7UUFDNUIsR0FBRztRQUNIO1lBQ0ksbUVBQW1FO1lBQ25FLG9CQUFvQjtTQUN2QjtLQUNKLENBQUM7SUFDRixLQUFJLElBQUksU0FBUyxJQUFJLHVCQUF1QixFQUFDO1FBQ3pDLE1BQU0sZUFBZSxHQUFHLHlCQUFlLENBQUMsUUFBUSxDQUFDO1lBQzdDLFFBQVEsRUFBRSxPQUFPO1lBQ2pCLFdBQVcsRUFBRTtnQkFDVCxLQUFLLEVBQUUsU0FBUzthQUNuQjtZQUNELFFBQVEsRUFBRSxDQUFDLGNBQWMsQ0FBQztZQUMxQixVQUFVLEVBQUU7Z0JBQ1IsdUJBQXVCO2dCQUN2Qix5QkFBeUI7YUFDNUI7WUFDRCxXQUFXLEVBQUU7Z0JBQ1QsV0FBVyxFQUFFO29CQUNULGtCQUFrQixFQUFFO3dCQUNoQixtQ0FBbUM7d0JBQ25DLGdEQUFnRDt3QkFDaEQsaURBQWlEO3FCQUNwRDtpQkFDSjthQUNKO1NBQ0osQ0FBQyxDQUFDO1FBQ0gsTUFBTSxjQUFjLEdBQUcsSUFBSSx3QkFBYyxFQUFFLENBQUM7UUFDNUMsY0FBYyxDQUFDLGFBQWEsQ0FBQyxlQUFlLENBQUMsQ0FBQztRQUM5QyxNQUFNLENBQUMsdUNBQXVCLENBQUMsY0FBYyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxHQUFHLEVBQVUsQ0FBQyxDQUFDO0tBQzlFO0FBRUwsQ0FBQyxDQUFDLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1BvbGljeURvY3VtZW50LCBQb2xpY3lTdGF0ZW1lbnR9IGZyb20gXCJAYXdzLWNkay9hd3MtaWFtXCI7XG5pbXBvcnQge2dldEFsbG93ZWRQcmluY2lwYWxBcm5zfSBmcm9tIFwiLi4vbGliL2F3cy1pYW0tdXRpbHNcIjtcblxudGVzdCgnZ2V0QWxsb3dlZFByaW5jaXBhbEFybnMgc2hvdWxkIHJldHVybiBlbXB0eSB3aGVuIFBvbGljeSBoYXMgbm8gc3RhdGVtZW50cycsICgpID0+IHtcbiAgICBleHBlY3QoZ2V0QWxsb3dlZFByaW5jaXBhbEFybnMobmV3IFBvbGljeURvY3VtZW50KCkpKS50b0VxdWFsKG5ldyBTZXQ8c3RyaW5nPigpKTtcbn0pO1xuXG50ZXN0KCdnZXRBbGxvd2VkUHJpbmNpcGFsQXJucyBzaG91bGQgcmV0dXJuIHByaW5jaXBhbCBmb3IgQWxsb3cgU3RhdGVtZW50IHdpdGggb25lIFByaW5jaXBhbCcsICgpID0+IHtcbiAgICBjb25zdCBleHBlY3RQcmluY2lwYWwgPSBcImFybjphd3M6aWFtOjoxMjM0NTY3ODkwMTI6cm9sZS9Tb21lLUN1c3RvbVMzQXV0b0RlbGV0ZU9iamVjdC1Sb2xlXCI7XG4gICAgY29uc3QgcG9saWN5U3RhdGVtZW50ID0gUG9saWN5U3RhdGVtZW50LmZyb21Kc29uKHtcbiAgICAgICAgICAgICAgICBcIkVmZmVjdFwiOiBcIkFsbG93XCIsXG4gICAgICAgICAgICAgICAgXCJQcmluY2lwYWxcIjoge1xuICAgICAgICAgICAgICAgICAgICBcIkFXU1wiOiBleHBlY3RQcmluY2lwYWxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIFwiQWN0aW9uXCI6IFtcInMzOkdldE9iamVjdCpcIiwgXCJzMzpHZXRCdWNrZXQqXCIsIFwiczM6TGlzdCpcIiwgXCJzMzpEZWxldGVPYmplY3QqXCJdLFxuICAgICAgICAgICAgICAgIFwiUmVzb3VyY2VcIjogW1xuICAgICAgICAgICAgICAgICAgICBcImFybjphd3M6czM6OjphLWJ1Y2tldFwiLFxuICAgICAgICAgICAgICAgICAgICBcImFybjphd3M6czM6OjphLWJ1Y2tldC8qXCJcbiAgICAgICAgICAgICAgICBdXG4gICAgICAgICAgICB9KTtcbiAgICBjb25zdCBwb2xpY3lEb2N1bWVudCA9IG5ldyBQb2xpY3lEb2N1bWVudCgpO1xuICAgIHBvbGljeURvY3VtZW50LmFkZFN0YXRlbWVudHMocG9saWN5U3RhdGVtZW50KTtcbiAgICBleHBlY3QoZ2V0QWxsb3dlZFByaW5jaXBhbEFybnMocG9saWN5RG9jdW1lbnQpKS50b0VxdWFsKG5ldyBTZXQ8c3RyaW5nPihbZXhwZWN0UHJpbmNpcGFsXSkpO1xufSk7XG5cbnRlc3QoJ2dldEFsbG93ZWRQcmluY2lwYWxBcm5zIHNob3VsZCByZXR1cm4gcHJpbmNpcGFscyBmb3IgQWxsb3cgU3RhdGVtZW50IHdpdGggbXVsdGlwbGUgUHJpbmNpcGFscycsICgpID0+IHtcbiAgICBjb25zdCBleHBlY3RQcmluY2lwYWwgPSBbXG4gICAgICAgIFwiYXJuOmF3czppYW06OjEyMzQ1Njc4OTAxMjpyb2xlL1NvbWUtQ3VzdG9tUzNBdXRvRGVsZXRlT2JqZWN0LVJvbGVcIixcbiAgICAgICAgXCIke1Rva2VuW1RPS0VOLjU1XX1cIlxuICAgICAgICBdO1xuICAgIGNvbnN0IHBvbGljeVN0YXRlbWVudCA9IFBvbGljeVN0YXRlbWVudC5mcm9tSnNvbih7XG4gICAgICAgICAgICAgICAgXCJFZmZlY3RcIjogXCJBbGxvd1wiLFxuICAgICAgICAgICAgICAgIFwiUHJpbmNpcGFsXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgXCJBV1NcIjogZXhwZWN0UHJpbmNpcGFsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBcIkFjdGlvblwiOiBbXCJzMzpHZXRPYmplY3QqXCIsIFwiczM6R2V0QnVja2V0KlwiLCBcInMzOkxpc3QqXCIsIFwiczM6RGVsZXRlT2JqZWN0KlwiXSxcbiAgICAgICAgICAgICAgICBcIlJlc291cmNlXCI6IFtcbiAgICAgICAgICAgICAgICAgICAgXCJhcm46YXdzOnMzOjo6YS1idWNrZXRcIixcbiAgICAgICAgICAgICAgICAgICAgXCJhcm46YXdzOnMzOjo6YS1idWNrZXQvKlwiXG4gICAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgfSk7XG4gICAgY29uc3QgcG9saWN5RG9jdW1lbnQgPSBuZXcgUG9saWN5RG9jdW1lbnQoKTtcbiAgICBwb2xpY3lEb2N1bWVudC5hZGRTdGF0ZW1lbnRzKHBvbGljeVN0YXRlbWVudCk7XG4gICAgZXhwZWN0KGdldEFsbG93ZWRQcmluY2lwYWxBcm5zKHBvbGljeURvY3VtZW50KSkudG9FcXVhbChuZXcgU2V0PHN0cmluZz4oZXhwZWN0UHJpbmNpcGFsKSk7XG59KTtcblxudGVzdCgnZ2V0QWxsb3dlZFByaW5jaXBhbEFybnMgc2hvdWxkIHNraXAgcHJpbmNpcGFscyBmb3IgQWxsb3cgU3RhdGVtZW50IHdoZW4gQ29uZGl0aW9ucyBleGlzdCcsICgpID0+IHtcbiAgICBjb25zdCBwcmluY2lwYWxFbGVtZW50c1RvVGVzdCA9IFtcbiAgICAgICAgXCIqXCIsXG4gICAgICAgIFtcbiAgICAgICAgICAgIFwiYXJuOmF3czppYW06OjEyMzQ1Njc4OTAxMjpyb2xlL1NvbWUtQ3VzdG9tUzNBdXRvRGVsZXRlT2JqZWN0LVJvbGVcIixcbiAgICAgICAgICAgIFwiJHtUb2tlbltUT0tFTi41NV19XCJcbiAgICAgICAgXVxuICAgIF07XG4gICAgZm9yKGxldCBwcmluY2lwYWwgb2YgcHJpbmNpcGFsRWxlbWVudHNUb1Rlc3Qpe1xuICAgICAgICBjb25zdCBwb2xpY3lTdGF0ZW1lbnQgPSBQb2xpY3lTdGF0ZW1lbnQuZnJvbUpzb24oe1xuICAgICAgICAgICAgXCJFZmZlY3RcIjogXCJBbGxvd1wiLFxuICAgICAgICAgICAgXCJQcmluY2lwYWxcIjoge1xuICAgICAgICAgICAgICAgIFwiQVdTXCI6IHByaW5jaXBhbFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIFwiQWN0aW9uXCI6IFtcInMzOkdldE9iamVjdFwiXSxcbiAgICAgICAgICAgIFwiUmVzb3VyY2VcIjogW1xuICAgICAgICAgICAgICAgIFwiYXJuOmF3czpzMzo6OmEtYnVja2V0XCIsXG4gICAgICAgICAgICAgICAgXCJhcm46YXdzOnMzOjo6YS1idWNrZXQvKlwiXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgXCJDb25kaXRpb25cIjoge1xuICAgICAgICAgICAgICAgIFwiQXJuRXF1YWxzXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IFtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiYXJuOmF3czppYW06OjEyMzQ1Njc4OTAxMjp1c2VyL2NpXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICBcImFybjphd3M6c3RzOjoxMzk3MTA0OTExMjA6ZmVkZXJhdGVkLXVzZXIvYWRtaW5cIixcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiYXJuOmF3czppYW06OjAxMjM0NTY3ODkwMTpyb2xlL2V4dGVybmFsLWF1ZGl0b3JcIixcbiAgICAgICAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHBvbGljeURvY3VtZW50ID0gbmV3IFBvbGljeURvY3VtZW50KCk7XG4gICAgICAgIHBvbGljeURvY3VtZW50LmFkZFN0YXRlbWVudHMocG9saWN5U3RhdGVtZW50KTtcbiAgICAgICAgZXhwZWN0KGdldEFsbG93ZWRQcmluY2lwYWxBcm5zKHBvbGljeURvY3VtZW50KSkudG9FcXVhbChuZXcgU2V0PHN0cmluZz4oKSk7XG4gICAgfVxuXG59KTtcblxuIl19