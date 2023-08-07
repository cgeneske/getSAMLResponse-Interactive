using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;

namespace getSAMLResponse
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            webView.CoreWebView2InitializationCompleted += WebView_CoreWebView2InitializationCompleted;
            InitializeAsync();
        }

        void WebView_CoreWebView2InitializationCompleted(object sender, CoreWebView2InitializationCompletedEventArgs e)
        {
            //Secure browser to prevent dev tools, right click, shortcut keys, swiping back and forth and autofill.
            webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            webView.CoreWebView2.Settings.AreBrowserAcceleratorKeysEnabled = false;
            webView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            webView.CoreWebView2.Settings.IsPasswordAutosaveEnabled = false;
            webView.CoreWebView2.Settings.IsSwipeNavigationEnabled = false;
            webView.CoreWebView2.Settings.IsGeneralAutofillEnabled = false;

            //Get commandline arguments, only one arg supported and should be the URL of the IDP initiated logon for the app. If no URL then throw an error.
            var commandLineArgs = Environment.GetCommandLineArgs();
            if (commandLineArgs.Length > 1)
            {
                string[] args = Environment.GetCommandLineArgs();
                string idpURL = args[1];
                webView.CoreWebView2.NavigationStarting += CoreWebView2_NavigationStarting;
                webView.CoreWebView2.NavigationCompleted += CoreWebView2_NavigationCompleted;
                webView.CoreWebView2.Navigate(idpURL);
            }
            else
            {
                throw new InvalidOperationException("No URL Passed. Must pass an IDP URL into app to start SAML Authentication process.");
            }
        }

        //Addresses potential race condition, preventing POST of SAMLResponse to PAM which would invalidate the assertion (triggering replay detection if subsequently attempted)
        private void CoreWebView2_NavigationStarting(object sender, CoreWebView2NavigationStartingEventArgs e)
        {
            if (e.Uri.Contains("PasswordVault/api/auth/saml/logon"))
            {
                e.Cancel = true;
            }
        }

        //Parse document body and scrape the SAMLResponse if the intended action would be a POST to CyberArk PAM
        private async void CoreWebView2_NavigationCompleted(object sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            string htmlEncoded = await webView.CoreWebView2.ExecuteScriptAsync("document.body.outerHTML");
            string htmlDecoded = Regex.Unescape(htmlEncoded);
            string regexAction = @"<form[^>]*action=""https:\/\/.+\/PasswordVault\/api\/auth\/saml\/logon""";
            Match actionMatch = Regex.Match(htmlDecoded, regexAction, RegexOptions.IgnoreCase);
            if (actionMatch.Success)
            {
                string regexSAML = @"(?<=name=""SAMLResponse""\svalue="")[^""]+";
                Match m = Regex.Match(htmlDecoded, regexSAML, RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    Console.Out.WriteLine(m.Value);
                    System.Windows.Forms.Application.Exit();
                }
                else
                {
                    throw new InvalidOperationException("Unable to match SAML Response to regex.");
                }
            }
        }

        async void InitializeAsync()
        {
            await webView.EnsureCoreWebView2Async(null);
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}