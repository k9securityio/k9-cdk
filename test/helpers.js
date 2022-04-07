"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stringifyPolicy = exports.stringifyStatement = void 0;
function stringifyStatement(policyStatement) {
    if (policyStatement) {
        return JSON.stringify(policyStatement.toStatementJson(), null, 2);
    }
    else {
        return "<none>";
    }
}
exports.stringifyStatement = stringifyStatement;
function stringifyPolicy(policyDocument) {
    if (policyDocument) {
        return JSON.stringify(policyDocument.toJSON(), null, 2);
    }
    else {
        return "<none>";
    }
}
exports.stringifyPolicy = stringifyPolicy;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGVscGVycy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImhlbHBlcnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBRUEsU0FBZ0Isa0JBQWtCLENBQUMsZUFBaUM7SUFDaEUsSUFBRyxlQUFlLEVBQUM7UUFDZixPQUFPLElBQUksQ0FBQyxTQUFTLENBQUMsZUFBZSxDQUFDLGVBQWUsRUFBRSxFQUFFLElBQUksRUFBRSxDQUFDLENBQUMsQ0FBQztLQUNyRTtTQUFNO1FBQ0gsT0FBTyxRQUFRLENBQUE7S0FDbEI7QUFDTCxDQUFDO0FBTkQsZ0RBTUM7QUFDRCxTQUFnQixlQUFlLENBQUMsY0FBK0I7SUFDM0QsSUFBRyxjQUFjLEVBQUM7UUFDZCxPQUFPLElBQUksQ0FBQyxTQUFTLENBQUMsY0FBYyxDQUFDLE1BQU0sRUFBRSxFQUFFLElBQUksRUFBRSxDQUFDLENBQUMsQ0FBQztLQUMzRDtTQUFNO1FBQ0gsT0FBTyxRQUFRLENBQUE7S0FDbEI7QUFDTCxDQUFDO0FBTkQsMENBTUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1BvbGljeURvY3VtZW50LCBQb2xpY3lTdGF0ZW1lbnR9IGZyb20gXCJAYXdzLWNkay9hd3MtaWFtXCI7XG5cbmV4cG9ydCBmdW5jdGlvbiBzdHJpbmdpZnlTdGF0ZW1lbnQocG9saWN5U3RhdGVtZW50PzogUG9saWN5U3RhdGVtZW50KSB7XG4gICAgaWYocG9saWN5U3RhdGVtZW50KXtcbiAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHBvbGljeVN0YXRlbWVudC50b1N0YXRlbWVudEpzb24oKSwgbnVsbCwgMik7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIFwiPG5vbmU+XCJcbiAgICB9XG59XG5leHBvcnQgZnVuY3Rpb24gc3RyaW5naWZ5UG9saWN5KHBvbGljeURvY3VtZW50PzogUG9saWN5RG9jdW1lbnQpIHtcbiAgICBpZihwb2xpY3lEb2N1bWVudCl7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShwb2xpY3lEb2N1bWVudC50b0pTT04oKSwgbnVsbCwgMik7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIFwiPG5vbmU+XCJcbiAgICB9XG59Il19