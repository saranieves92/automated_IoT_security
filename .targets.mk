
draft-garcia-threats-PASC-mitigation-profiles-00.xml: draft-garcia-threats-PASC-mitigation-profiles.xml
	sed -e '$(join $(addprefix s/,$(addsuffix -latest/,$(drafts))), $(addsuffix /g;,$(drafts_next)))' $< > $@
diff-draft-garcia-threats-PASC-mitigation-profiles-.txt.html: draft-garcia-threats-PASC-mitigation-profiles-.txt draft-garcia-threats-PASC-mitigation-profiles.txt
	-$(rfcdiff) --html --stdout $^ > $@
