"""
Stop words in different languages.
"""
__author__ = "Alisher Mazhirinov"

english_stopwords = set("""
i me my myself we our ours ourselves you your yours yourself yourselves he him his himself she her hers herself 
it its itself they them their theirs themselves what which who whom this that these those am is are was were be 
been being have has had having do does did doing a an the and but if or because as until while of at by for with 
about against between into through during before after above below to from up down in out on off over under again 
further then once here there when where why how all any both each few more most other some such no nor not only 
own same so than too very s t can will just don should now d ll m o re ve y ain aren couldn didn doesn hadn hasn 
haven isn ma mightn mustn needn shan shouldn wasn weren won wouldn gx tz add one get may feb mar apr may jun jul aug sep oct 
nov dec jan february march april may june july august september october november december january 
one two three four five six seven eight nine ten us ago after before during next last first second third 
fourth fifth sixth seventh eighth ninth tenth top bottom left right center middle up down east west north south 
pm am ams pm pms see day days week weeks month months year years back forward today tomorrow yesterday now later soon 
""".split())

german_stopwords = set("""
aber alle allem allen aller alles als also am an ander andere anderem anderen anderer anderes andeutend andeutende 
andeutender andeutendes auch auf aus ausser außer bei bin bist dass das da damit dann das der den des dem die 
doch dort du durch ein eine einem einen einer eines einig einige ebenfalls eben eher ein einmal er erst erste 
ersten erster erstes etwas euch euer eure für gegen gewesen gewiss gewöhnlich hast hat hatte hatten hattest hattet 
heute hier hin hinter ich ihm ihn ihnen ihr ihre im immer in indem ins ist jede jedem jeden jeder jedes jener jenes 
jetzt kann kein keine keinem keinen keiner keines können könnte man manche manchem manchen mancher manches mein 
meine mit musste nach nicht nichts noch nun nur ob oder ohne sehr sein seine sich sie sind so solche soll sollte 
sonst soweit sowie über um und uns unser unter vom von vor war waren wart was weiter welche welchem welchen welcher 
welches wenn wer werde werden wie wieder will wir wird wirst wo wollen wollte während würde würden zu zum zur zwar 
zwischen über gx
""".split())

spanish_stopwords = set("""
a algún alguna algunas alguno algunos ante antes con contra cual cualquier cuando de del desde donde dos durante 
e el ella ellas ello ellos en entre era erais éramos eran eras eres es esta estaba estabais estábamos estaban 
estabas estad estado estais estamos están estando estar estará estarán estarás estaré estaréis estaremos estaría 
estaríais estaríamos estarían estarías estás este estos estoy estuvo fuimos fueron fuiste fuisteis ha habéis había 
habíais habíamos habían habías han has hasta hay haya hayáis hayamos hayan hayas he hemos hube hubiera hubierais 
hubiéramos hubieran hubieras hubieron hubiese hubieseis hubiésemos hubiesen hubieses hui huyó iba ibais íbamos iban 
ibas id ido ir irás iré iréis iremos iría iríais iríamos irían irías la las le les lo los me mi mis mucho mucha 
muchos muchas muy nosotros nosotras nos nuestro nuestra nuestros nuestras o os para pero poco por porque que quien 
quienes qué se sea seáis seamos sean seas ser será serán serás seré seréis seremos sería seríais seríamos serían 
serías si sido siempre siendo sobre sois somos son soy su sus te tendrá tendrán tendrás tendré tendréis tendremos 
tendría tendríais tendríamos tendrían tendrías tenía teníais teníamos tenían tenías tengo tenía ti tu tus tú un una 
unas uno unos vosotras vosotros vuestra vuestro vuestras vuestros y ya yo gx
""".split())

french_stopwords = set("""
alors au aucun aujourd hui autre avant avec avoir bon car ce cela ces chaque comme comment dans des du donc 
dos droite deux également elle elles en encore est et eu fait faites fois font hors ici il ils je juste la le 
les leur là ma maintenant mais même mes mine moi moins mon mot néanmoins non nos notre nous nouveaux ou où 
par parce part pas peut peu plutôt pour pourquoi quand que quel quelle quels qui sa sans ses seulement si 
sien son sont sous soyez sujet sur ta tandis tellement tenez tes ton tous tout toutes toujours très trop tu 
un une valeur voir vôtre vous vu ça étaient état étions être gx
""".split())

russian_stopwords = set("""
и в во не что он на я с со как а то все она так его но да ты к у же вы за бы по только ее мне было вот от 
меня еще нет о из ему теперь когда даже ну вдруг ли если уже или ни быть был него до вас нибудь опять уж 
вам сказали говорил говорила тем кто этот сам чтоб без будто чего раз тоже себя ни один тут там потом 
себе под чем будет этим более всех между gx
""".split())

czech_stopwords = set("""
a aby aj ak ale ani áno asi až bez bude budete budem budeme budeš budou bych bychom bys byste by byl byla byli 
bylo být co či dál dnes do dobrý ho jak já je jeho jej jeho její jejich jen jeden ještě ji jich jim jimi jinak 
jsem jsme jsi jsou jste že že k když ke kdo kde ktera které který kterou kteří ku má mám máme mají mít mi mohl 
může můžeme můžete můj na nám námi nás náš není nic něco nebo něj není nepříliš než nic něco nový nyní od 
ode on ona oni ono pod podle potom protože pro před přede přece přes při proč proto rovněž se si svého své 
svůj svých svým svými ta tak také tam tento této tím tímto to toho tohoto tom tomto tou tu tuto tvůj tvá 
tvé tvůj ty určitě už v vám vámi vás váš ve vedle všeho všem všemi vždy z za zda zde ze že gx
""".split())
