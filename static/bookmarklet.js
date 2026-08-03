javascript:(function(){
  var ZW={8203:"ZERO WIDTH SPACE",8204:"ZERO WIDTH NON-JOINER",8205:"ZERO WIDTH JOINER",8288:"WORD JOINER",65279:"BOM",173:"SOFT HYPHEN",6158:"MONGOLIAN VOWEL SEP",1564:"ARABIC LETTER MARK"};
  var BD={8234:"LRE",8235:"RLE",8236:"PDF",8237:"LRO",8238:"RLO",8294:"LRI",8295:"RLI",8296:"FSI",8297:"PDI",8206:"LRM",8207:"RLM"};
  var HG={"а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","і":"i","ѕ":"s","ο":"o","α":"a","ε":"e","ρ":"p","υ":"u","ι":"i"};
  var sel=(window.getSelection&&String(window.getSelection()))||"";
  var t=sel||prompt("Paste text to reveal hidden Unicode:","");
  if(t==null)return;
  function U(c){return"U+"+c.toString(16).toUpperCase().padStart(4,"0");}
  function E(s){return String(s).replace(/[&<>"']/g,function(x){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[x];});}
  var i=0,rev="",hits=[];
  for(var ch of t){var cp=ch.codePointAt(0),cat=null,note="";
    if(ZW[cp]){cat="zero-width";}
    else if(BD[cp]){cat="bidi";}
    else if(cp>=917504&&cp<=917631){cat="tag-block";var m=cp-917504;if(m>=32&&m<=126)note="~ASCII '"+String.fromCharCode(m)+"'";}
    else if((cp>=65024&&cp<=65039)||(cp>=917760&&cp<=917999)){cat="var-selector";}
    else if(HG[ch]){cat="homoglyph";note="looks like '"+HG[ch]+"'";}
    else if(cp>=65281&&cp<=65374){cat="homoglyph";note="fullwidth->'"+String.fromCodePoint(cp-65248)+"'";}
    else if(ch==="ı"||ch==="İ"){cat="casefold-trap";note="Turkish dotless-i";}
    var inv=cat==="zero-width"||cat==="bidi"||cat==="tag-block"||cat==="var-selector";
    if(cat){hits.push([ch,cp,cat,i,note]);rev+="<mark style='background:#fde68a;color:#7c2d12'>"+(inv?U(cp):E(ch))+"</mark>";}
    else{rev+=E(ch);}
    i++;}
  var rows=hits.map(function(h){return"<tr><td>"+(["zero-width","bidi","tag-block","var-selector"].indexOf(h[2])>=0?U(h[1]):E(h[0]))+"</td><td>"+U(h[1])+"</td><td>"+h[3]+"</td><td>"+E(h[2])+"</td><td>"+E(h[4])+"</td></tr>";}).join("");
  var d=document.createElement("div");
  d.style.cssText="position:fixed;inset:5%;z-index:2147483647;background:#0f172a;color:#e2e8f0;padding:20px;border-radius:12px;overflow:auto;font:14px system-ui;box-shadow:0 10px 40px rgba(0,0,0,.5)";
  d.innerHTML="<button style='float:right;font:14px system-ui;padding:4px 10px;cursor:pointer' onclick='this.parentNode.remove()'>close</button><h2 style='margin:0 0 8px'>🔍 unicode-threat-reveal</h2><p>"+(hits.length?hits.length+" suspicious char(s)":"clean — no known-evasion chars")+"</p><div style='font-family:monospace;white-space:pre-wrap;word-break:break-word;line-height:2;background:#020617;padding:12px;border-radius:8px'>"+rev+"</div>"+(hits.length?"<table style='margin-top:12px;border-collapse:collapse;width:100%' border='1' cellpadding='4'><tr><th>char</th><th>codepoint</th><th>idx</th><th>class</th><th>note</th></tr>"+rows+"</table>":"");
  document.body.appendChild(d);
})();
