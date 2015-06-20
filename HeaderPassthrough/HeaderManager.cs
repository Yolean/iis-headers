using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Collections.Specialized;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace HeaderPassthrough
{
    public class HeaderManager : IHttpModule
    {


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
                        if (user_principal.DistinguishedName != null)
                        {
                            headers.Add("USER_DISTINGUISHED_NAME", user_principal.DistinguishedName);
                        }
                        if (user_principal.EmailAddress != null)
                        {
                            headers.Add("USER_EMAIL_ADDRESS", user_principal.EmailAddress);
                        }
                        if (user_principal.DisplayName != null)
                        {
                            headers.Add("USER_DISPLAY_NAME", user_principal.DisplayName);
                        }
                        if (user_principal.GetGroups() != null)
                        {
                            int counter = 0;
                            foreach(GroupPrincipal group in user_principal.GetGroups())
                            {
                                headers.Add("USER_GROUP_" + counter.ToString(), group.ToString());
                                counter++;
                            }
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
