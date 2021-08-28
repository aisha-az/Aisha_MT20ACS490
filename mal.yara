rule MAL_Ursnif_Ru {
   meta:
      description = "Detects a suspicious string often used in EXE files in a hex encoded object stream"
      author = "Aisha"
      date = "2021-08-25"
   strings:
     $a= "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL"
	 $b= "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE"
	 $c= "C:\\Windows\\System32\\stdole2.tlb"
	 $d= "C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL"
	 $e= "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL"
   condition:
      $a and $b and $c and any of ($d,$e)
	  
	  }