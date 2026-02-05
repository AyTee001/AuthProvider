using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;

namespace AuthProvider.Attributes;

public class FormValueAttribute(string name) : ActionMethodSelectorAttribute
{
    private static class RequestMethods
    {
        public const string HEAD = "HEAD";
        public const string Get = "GET";
        public const string Trace = "TRACE";
        public const string Delete = "DELETE";
    }

    private readonly string _formContentType = "application/x-www-form-urlencoded";

    private readonly string _name = name;

    public override bool IsValidForRequest(RouteContext routeContext, ActionDescriptor action)
    {
        var requestMethod = routeContext.HttpContext.Request.Method;
        var stringComparisonMode = StringComparison.OrdinalIgnoreCase;

        if (string.Equals(requestMethod, RequestMethods.Get, stringComparisonMode)
            || string.Equals(requestMethod, RequestMethods.Delete, stringComparisonMode)
            || string.Equals(requestMethod, RequestMethods.Trace, stringComparisonMode)
            || string.Equals(requestMethod, RequestMethods.HEAD, stringComparisonMode))
        {
            return false;
        }

        if (string.IsNullOrEmpty(routeContext.HttpContext.Request.ContentType))
        {
            return false;
        }

        if (!routeContext.HttpContext.Request.ContentType.StartsWith(_formContentType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !string.IsNullOrEmpty(routeContext.HttpContext.Request.Form[_name]);
    }
}
