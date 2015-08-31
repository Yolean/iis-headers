using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Collections.Specialized;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace LogonPassthrough
{
    public class HeaderManager : IHttpModule
    {

        private const String NOT_SET = "Undefined";

        public void Dispose()
        {
            //Not sure we have to do anything here
        }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest +=
                new EventHandler(ProcessRequest);
        }

        // For development purposes
        private void addMap(string label, NameValueCollection coll, HttpApplication application)
        {
            string[] keys = coll.AllKeys;
            application.Context.Response.Output.WriteLine(label + ":<br>\n");
            for (int i = 0; i < keys.Length; i++)
            {
                application.Context.Response.Output.WriteLine(i + " => " + keys[i] + " => " + coll.Get(keys[i]) + "<br>\n");
            }
        }

        private void addHeader(NameValueCollection headers, String headerName, String headerValue)
        {
            if (headerValue == null)
            {
                headers.Add(headerName, NOT_SET);
            }
            else
            {
                headers.Add(headerName, headerValue);
            }
        }

        public void ProcessRequest(Object source, EventArgs e)
        {
            HttpApplication application = (HttpApplication) source;
            if (application.Context.Request.ServerVariables.AllKeys.Contains("LOGON_USER"))
            {
                String logon_user = application.Context.Request.ServerVariables.Get("LOGON_USER");
                String[] logon_user_parts = logon_user.Split('\\');
                if (logon_user_parts.Length == 2)
                {
                    // Should be something like EU, or SVEALIDEN in my test setup.
                    String domain = logon_user_parts[0];
                    // Should be Administrator or jolofsson or something like that.
                    String username = logon_user_parts[1];

                    // Let's get a context for the domain this user belongs to.
                    PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domain);
                    Principal user = new UserPrincipal(principalContext); // Empty user to use for our search
                    user.SamAccountName = username;
                    PrincipalSearcher searcher = new PrincipalSearcher(user);
                    UserPrincipal user_principal = (UserPrincipal) searcher.FindOne();
                    if (user_principal != null)
                    {
                        var headers = application.Context.Request.Headers;
                        if (user_principal.EmailAddress == null || user_principal.EmailAddress.Equals("no_mail"))
                        {
                            // Unusual case, probably only for admin users. Safe fallback?
                            addHeader(headers, "X-Logon-AccountName", user_principal.SamAccountName);
                        }
                        else
                        {
                            addHeader(headers, "X-Logon-AccountName", user_principal.EmailAddress);
                        }
                        addHeader(headers, "X-Logon-DistinguishedName", user_principal.DistinguishedName);
                        addHeader(headers, "X-Logon-EmailAddress", user_principal.EmailAddress);
                        addHeader(headers, "X-Logon-DisplayName", user_principal.DisplayName);
                        addHeader(headers, "X-Logon-DomainUserName", user_principal.SamAccountName);

                        if (user_principal.GetGroups() != null)
                        {
                            String groups = "";
                            foreach (GroupPrincipal group in user_principal.GetGroups())
                            {
                                groups += group.ToString() + ",";
                            }
                            int lastChar = groups.Length - 1;
                            if (groups[lastChar].Equals(','))
                            {
                                groups = groups.Remove(lastChar);
                            }
                            headers.Add("X-Logon-Groups", groups);
                        }
                        else
                        {
                            headers.Add("X-Logon-Groups", NOT_SET);
                        }
                    }
                    else
                    {
                        throw new HttpException(403, "No such user principal");
                    }
                }
            }
            else
            {
                throw new HttpException(403, "User information was poorly formatted.");
            }
        }
    }
}
