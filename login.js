module.exports = `<% title = 'eIdLab.ch Ecosystem' %>
<p>Demo OpenID Connect Identity Provider within the eIdLab.ch Ecosystem.<br><br>
Notice: Name and password are freely selectable and are only stored temporarily during the session.<br></p>
<form autocomplete="off" action="<%- action %>" method="post">
  <input type="hidden" name="view" value="login"/>
  <input required type="text" name="login" placeholder="Enter any login" <% if (!params.login_hint) { %>autofocus="on"<% } else { %> value="<%= params.login_hint %>" <% } %>>
  <input required type="password" name="password" placeholder="and password" <% if (params.login_hint) { %>autofocus="on"<% } %>>

  <label><input type="checkbox" name="remember" value="yes" checked="yes">Stay signed in</label>

  <button type="submit" name="submit" class="login login-submit">Sign-in</button>
</form>`;
