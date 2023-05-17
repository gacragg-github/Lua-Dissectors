-- ieee11073.lua
-- https://wiki.wireshark.org/uploads/5480731fd0e9a6da06fb9616cceb80c7/220701_sf22us_duct_tape_as_presented.pdf
-- Sample capture: httptest.pcapng
-- Check out: 	https://wiki.wireshark.org/Lua/Examples#extract-field-values
--				https://wiki.wireshark.org/Lua/Examples/PostDissector
--				https://ask.wireshark.org/question/16067/80211-lua-dissector/
--
--	Versions
--	0.0.2	Partial call outs for Ipfe0-33 data
--	0.0.3	Bring out waveform samples for Ipfe0-33
--	0.0.3a	Bring out waveform samples for ....
--	0.0.3b	Improve handling of DescriptonHandle string

-- Step 1 - document as you go. See header above and set_plugin_info().
local IEEE11073_info =
{
	version = "0.0.4",
	author = "Good Coder",
	description = "IEEE11073 Protocol to pull out specific elements",
	repository = "Nowhere"
}
set_plugin_info(IEEE11073_info)

--Config DEBUG - will print values.  Set to true or false.
-- DEBUG = false | true
local DEBUG = true
--local DEBUG = false

--General config variables
local FieldNotPresent = "NotPresent"

-- calling tostring() on random FieldInfo's can cause an error, so this func handles it
local function getstring(finfo)
    local ok, val = pcall(tostring, finfo)
    if not ok then val = "(unknown)" end
    return val
end

-- Debug print construct for troubleshooting
--e.g. debug(pinfo.number, "Report: ", report)
local function debug(frameid, text, str)
	if DEBUG and text ~= nil and str ~=nil then 
		print("[" ..frameid.. "] " .. text .. " " .. str)
	end
end

--Extract Action information from URI
local function action_extract(frameid, actionmsg)
	if string.len(actionmsg) > 0 then
		debug(frameid, "Dissect Action", actionmsg)
		actionmsg=string.gsub(actionmsg,"action=","") 		--> strip 'action=' text
		actionmsg=string.gsub(actionmsg,"[\"]", "") 		--> strip ' " ' text
		debug(frameid, "Dissect Action, cleaned", actionmsg)
		local actionmsgtable = split(actionmsg,'[\\/]+')
		for ix, token in ipairs(actionmsgtable) do
			debug(frameid, "["..ix.."] ", token)
		end	
		service = (string.gsub(table.concat(actionmsgtable, '\n', #actionmsgtable - 1, #actionmsgtable -1), "[\"]", ""))
		report = (string.gsub(table.concat(actionmsgtable, '\n', #actionmsgtable, #actionmsgtable), "[\"]", ""))	
	
		--Results table
		--	[1] actionstring
		--	[2] service
		--	[3] report
		local actionresulttable = {}
		actionresulttable[1] = actionmsg
		actionresulttable[2] = service
		actionresulttable[3] = report
		
		debug(frameid, "Action from http.content_type ", actionmsg)
		debug(frameid, "Service from http.content_type ", service)
		debug(frameid, "Report from http.content_type ", report)	
	
		return actionresulttable
	end
end		

local function table_min_statever(table)
	--We want to return { statever, determinationtime} of the minimum state version and will use dtime in some calculations
	--table format is expected to be { ndx, {statever, determinationtime}}
	local minstatever = math.huge
	local mindtime = 0
	for index, state_dtime in ipairs(table) do 
		statever = tonumber(state_dtime[1])
		dtime = tonumber(state_dtime[2])
		minstatever = minstatever < statever and minstatever or statever
		if minstatever == statever then
			mindtime = dtime
		end
	end
	return {minstatever, mindtime}
end

local function max_array(frameid, table)
	--Step through table, looking for max
	--table in will be { ndx, {statever, determinationtime}}
	--Out result will be { statever, determinationtime} of max statever
	for j, k in ipairs(table) do 
		--debug(frameid, j, table.concat(k, ", ")) 
		debug(frameid, j, k[1] .." / " .. k[2]) 
	end
	local localmaxstate = 0
	local localmaxdtime = 0
	local i,j, localstatever, localdtime
	for i,j in ipairs(table) do
		localstatever = tonumber(j[1])
		localdtime = tonumber(j[2])
		if localstatever > localmaxstate then
			localmaxstate = localstatever
			localmaxdtime = localdtime
		end
	end	
	debug(frameid, "Max table result: ", "State: " .. localmaxstate .. " dTime: " .. localmaxdtime)
	return 	{localmaxstate, localmaxdtime}
end

local function find_previous_statever(frameid, statevertable, currentstatever)
	--Step through table, looking for previous state version entry to current
	--statevertable in will be { ndx, {statever, determinationtime}}
	--currentstatever in will be statever
	--Out result will be { statever, determinationtime} of previous entry to the current
	
	--Loop through statevertable; if .gt. or .eq. than currentstatever, insert into new temp table
	--then find max
	local i,j
	local temptable = {}
	for i,j in ipairs(statevertable) do
		localstatever = tonumber(j[1])
		if localstatever < currentstatever then
			table.insert(temptable, j)
		end
	end	
	debug(frameid, "Test reduced dataset statevertable against ", currentstatever)
	for j, k in ipairs(temptable) do 
		debug(frameid, j, table.concat(k, ", ")) 
	end
	debug(frameid, "Length of table for finding previous value: ", #temptable)
	--With reduced table, find max - if first entry, then return itself
	if temptable == nil or #temptable < 1 then
		for i,j in ipairs(statevertable) do
			localstatever = tonumber(j[1])
			if localstatever == currentstatever then
				return {currentstatever, j[2]}
			end	
		end	
	else
		return max_array(frameid, temptable)
	end	
end 


--Split a string on a specific pattern
--	Return a table of split values
function split(str, pat)
   local t = {}  -- NOTE: use {n = 0} in Lua-5.0
   local fpat = "(.-)" .. pat
   local last_end = 1
   local s, e, cap = str:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
         table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
   end
   if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
   end
   return t
end

--Split a file path string into components.
function split_path(str)
   return split(str,'[\\/]+')
end

-- Step 2 - create a protocol to attach new fields to
local IEEE11073_p = Proto.new("IEEE11073","IEEE11073 SDC Protocol")

function IEEE11073_p.init()
	Ipfe33_time = {}		--> state version @ determination time - running table
	mdib_time = {}			--> mdib version @ packet time - running table
end

-- Step 3 - add some field(s) to Step 2 protocol
local pf = {
	target_host = ProtoField.string("IEEE11073.target", "IEEE11073 IP target"),
	source_host = ProtoField.string("IEEE11073.source", "IEEE11073 IP source"),
	frame_no = ProtoField.int32("IEEE11073.frame_no", "IEEE11073 frame number"),
	frame_time = ProtoField.double("IEEE11073.frame_time", "IEEE11073 frame time"),
	frame_time_hr = ProtoField.string("IEEE11073.frame_time_hr", "IEEE11073 frame time HR format"),
	http_request_method = ProtoField.string("IEEE11073.http_request_method", "IEEE11073 HTTP Request Method"),
	xml_cdata_raw = ProtoField.string("IEEE11073.raw_xml", "IEEE11073 raw xml"),
	sdc_action = ProtoField.string("IEEE11073.sdc_action", "IEEE11073 SDC Action"),
	sdc_service_type = ProtoField.string("IEEE11073.sdc_service", "IEEE11073 SDC Service"),
	sdc_report_type = ProtoField.string("IEEE11073.sdc_report_type", "IEEE11073 SDC Report Type"),
	sdc_report_size = ProtoField.string("IEEE11073.sdc_report_size", "IEEE11073 SDC Report Size [bytes]"),
	report_mdib_version = ProtoField.string("IEEE11073.report_mdib_version", "IEEE11073 Report MDIB Version"),
	dummy = ProtoField.string("IEEE11073.dummy", "IEEE11073 Dummy Field"),
	Ipfe0_33 = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33", "IEEE11073 Ipfe0-33"),
	Ipfe0_33_DescriptorHandle = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33.DescriptorHandle", "IEEE11073 Ipfe0-33 DescriptorHandle"),
	Ipfe0_33_DeterminationTime = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33.DeterminationTime", "IEEE11073 Ipfe0-33 DeterminationTime"),
	Ipfe0_33_DeterminationTimeHR = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33.DeterminationTimeHR", "IEEE11073 Ipfe0-33 DeterminationTime HR"),
	Ipfe0_33_StateVersion = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33.StateVersion", "IEEE11073 Ipfe0-33 StateVersion"),
	Ipfe0_33_Validity = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33.Validity", "IEEE11073 Ipfe0-33 Validity"),
	Ipfe0_33_DTime_sinceFirst = ProtoField.uint32("IEEE11073.Ipfe0-33.DeterminationTime.SinceFirst", "IEEE11073 Ipfe0-33 DeterminationTime since First Report"),
	Ipfe0_33_DTime_sinceLast = ProtoField.uint32("IEEE11073.Ipfe0-33.DeterminationTime.SinceLast", "IEEE11073 Ipfe0-33 DeterminationTime since Last Report"),
	Ipfe0_33_Samples = ProtoField.string("IEEE11073.Waveforms.Ipfe0-33.Samples", "IEEE11073 Ipfe0-33 Samples"),
	IpfeDevice = ProtoField.string("IEEE11073.ipfe.device", "IEEE11073 Ipfe Device"),
	DescriptorHandle = ProtoField.string("IEEE11073.Waveforms.DescriptorHandle", "IEEE11073 DescriptorHandle"),
	DeterminationTime = ProtoField.string("IEEE11073.Waveforms.DeterminationTime", "IEEE11073 DeterminationTime"),
	DeterminationTimeHR = ProtoField.string("IEEE11073.Waveforms.DeterminationTimeHR", "IEEE11073 DeterminationTime HR"),
	StateVersion = ProtoField.string("IEEE11073.Waveforms.StateVersion", "IEEE11073 StateVersion"),
	Validity = ProtoField.string("IEEE11073.Waveforms.Validity", "IEEE11073 Validity"),
	Samples = ProtoField.string("IEEE11073.Waveforms.Samples", "IEEE11073 Waveforms Samples")
}
IEEE11073_p.fields = pf
	--At this point, View --> Internals --> Supported Protocols --> IEEE11073 will show fields

-- Step 4 - create a Field extractor to copy packet field data.
local ip_target_f = Field.new("ip.dst")
local ip_source_f = Field.new("ip.src")
local frame_no_f = Field.new("frame.number")
local frame_time_f = Field.new("frame.time_epoch")
local http_request_method_f = Field.new("http.request.method")
local sdc_report_size_f = Field.new("http.file_data")
local xml_cdata_raw_f = Field.new("xml.cdata")
local xml_f = Field.new("xml")
local http_content_type_f = Field.new("http.content_type")



-- Step 5 - create the postdissector function that will run on each frame/packet
function IEEE11073_p.dissector(tvbbuffer,pinfo,tree)

	--Dtermine if we have the right kind of message, then process
	--Set locations of where to get info - want to know
		-- 1. do we have application/soap+xml
		--		if so, add basic frame elements
		-- 2. do we have action= field.  Could be in http.content_type or as part of action in xml header.
		--		if so, add action / service / report

	--Start with http.content_type for soap+xml and maybe action
	--local httpcontenttype = { http_content_type_f() }
	local httpcontenttype = getstring(http_content_type_f())
	
	--Process action string to get at Service/Report types
	http_content_type_split = split(httpcontenttype, ";")

	local k, v, i, j, ndx, value, state1, val
	local issoapxmlmsg = 0
	local isactionmsg = 0
	local actionmsg = ''
	local reporttype
	local body_str
	debug(pinfo.number, "Checking http.content_type", '')
	for ix, token in ipairs( http_content_type_split ) do
		debug(pinfo.number, "  Raw token [" .. ix .."] ", token)
		--Is this soap+xml
		local contentcheck = string.find(token, "application/soap+xml",1,true)
		if contentcheck ~= nil then
			debug(pinfo.number, "    Soap check [" .. ix .."] ", contentcheck)
			issoapxmlmsg = 1
		else
			debug(pinfo.number, "    Soap check [" .. ix .."] ", "nil")
		end
		local actionstrstart = string.find(token, "action=",1,true)
		if actionstrstart ~= nil then
			debug(pinfo.number, "    Action check [" .. ix .."] ", actionstrstart)
			isactionmsg = 1
			actionmsg = token
		else
			debug(pinfo.number, "    Action check [" .. ix .."] ", "nil")
		end
	end	

	debug(pinfo.number, "Did we have a soap+xml content string?", soapxmlmsg)
	if isactionmsg > 0 then
		debug(pinfo.number, "Action msg found in http.content_type", actionmsg)
	else
		debug(pinfo.number, "Action msg not found in http.content_type", actionmsg)
	end	
		
	--Now that we have soap+xml we can move forward
	if issoapxmlmsg > 0 then
		debug(pinfo.number, "We have a soap msg", 'continue')
	else
		debug(pinfo.number, "No soap msg, return", 'bye')
		return
	end	

	
--Setup trees for disection pane
	local subtree = nil
	local frametree
	local sdctree
	if not subtree then
		subtree = tree:add(IEEE11073_p)
	end
	if issoapxmlmsg > 0 then 
		frametree = subtree:add("IEEE11073 Frame Info")
		sdctree = subtree:add("IEEE11073 SDC Info")
	end	

	-- copy existing field(s) into table for processing
	local finfo6 = { xml_cdata_raw_f() }
	for k, v in pairs({ frame_no_f() }) do
		-- process data and add results to the tree
		frametree:add(pf.frame_no, v.display)
	end
	for k, v in pairs({ frame_time_f() }) do
		frametree:add(pf.frame_time, pinfo.abs_ts)
	end
	frametree:add(pf.frame_time_hr, os.date("%x %X", pinfo.abs_ts))
	for k, v in pairs({ ip_source_f() }) do
		frametree:add(pf.source_host, v.display)
	end
	for k, v in pairs({ ip_target_f() }) do
		frametree:add(pf.target_host, v.display)
	end
	for k, v in pairs({ http_request_method_f() }) do
		frametree:add(pf.http_request_method, v.display)
	end
			
	--if we have action= in http.content_type, process
	local service
	local report
	if string.len(actionmsg) > 0 then
		debug(pinfo.number, "Dissect Action from http.content", actionmsg)
		action_result_table = action_extract(pinfo.number, actionmsg)
		
		sdctree:add(pf.sdc_action, action_result_table[1])
		sdctree:add(pf.sdc_service_type, action_result_table[2])
		sdctree:add(pf.sdc_report_type, action_result_table[3])
		reporttype = action_result_table[3]
	end		

	--Collect report size - if there is xml data to parse, this should be > 0
	local report_size
	for k, v in pairs( {sdc_report_size_f()} ) do
		debug(pinfo.number, "Report size raw ", v.display)
		local sbufraw = v.tvb
		report_size = sbufraw:len()
		sdctree:add(pf.sdc_report_size, report_size)
		debug(pinfo.number, "Report size [bytes] ", report_size)
		if report_size == 0 or report_size == nil then
			debug(pinfo.number, "Report size is 0", "bye")
			return
		end	
	end


	if report_size ~= nil and report_size > 0 then 
	--Bulk processing of xml
		local counter = 0	--> simple counter
		for k, v in pairs( { xml_f() } ) do
			local sbufraw = v.tvb
			local sbuf = sbufraw:string()
			local sbufLength = sbufraw:len()
			
			--Find Envelope
			--Envelope contains Body Header and Body as well as xml schema definitions
			local i,j,envelope_str
			i, j, envelope_str = string.find(sbuf, "<[%a%d%-]*:Envelope>*(.-)</[%a%d%-]*:Envelope>")
			if not envelope_str then 
				envelope_str = "No envelope identified"
			end	
			--debug(pinfo.number, "Envelope: ", envelope_str)
			
			--Find Header inside envelope
			local header_str
			i, j, header_str = string.find(envelope_str, "<[%a%d%-]*:Header>(.-)</[%a%d%-]*:Header>")
			if not header_str then 
				header_str = "No header identified"
			end
			--debug(pinfo.number, "Header: ", header_str)
			
			--Find Body inside envelope
			i, j, body_str = string.find(envelope_str, "<[%a%d%-]*:Body>(.-)</[%a%d%-]*:Body>")
			if not body_str then 
				body_str = ""
				debug(pinfo.number, "Body: ", body_str)
				--break 
			end
			
			--With HDR identified, find action sequence and process
			local action_str
			i, j, action_str = string.find(header_str, "<[%a%d%-]*:Action.->(.-)</[%a%d%-]*:Action>")
			if not action_str then 
				action_str = "No action identified"
				--break 
			end
			debug(pinfo.number, "Action_str from xml hdr: ", action_str)
			if string.len(action_str) > 0 and isactionmsg == 0 then
				debug(pinfo.number, "Dissect Action from xml_body", action_str)
				action_result_table = action_extract(pinfo.number, action_str)
		
				sdctree:add(pf.sdc_action, action_result_table[1])
				sdctree:add(pf.sdc_service_type, action_result_table[2])
				sdctree:add(pf.sdc_report_type, action_result_table[3])
				reporttype = action_result_table[3]
			end		
			
			if not (reporttype == "GetMdibResponse") then 
				--With body found, mdib is an attribute here
				local mdibversion_report
				--https://stackoverflow.com/questions/42206244/lua-find-and-return-string-in-double-quotes
				mdibversion_report = string.match( body_str,[[MdibVersion="([%d]+)"]] )
				if not mdibversion_report then
					mdibversion_report = FieldNotPresent
				end	
				debug(pinfo.number, "mdibversion_report: " .. counter, mdibversion_report)
				sdctree:add(pf.report_mdib_version, mdibversion_report)
			end	
		end	
	end

	local mdibversion_report
	if reporttype == "GetMdibResponse" then 
		if DEBUG then print("Type GetMdibResponse") end
		local sbufraw = xml_f().tvb
		local sbuf = sbufraw:string()
		local sbufLength = sbufraw:len()
		mdibversion_report = string.match( sbuf,[[MdibVersion="([%d]+)"]] )
		if not mdibversion_report then
			mdibversion_report = FieldNotPresent
		end	
		debug(pinfo.number, "mdibversion_report: ", mdibversion_report)
		sdctree:add(pf.report_mdib_version, mdibversion_report)
	end	
	
	--Collect IPFE details for WaveformStream
	if reporttype == "WaveformStream" then
		--Setup waveform tree=
		local waveformstree2 = subtree:add("IEEE11073 All Ipfe Devices")

		debug(pinfo.number, "xml.body.len", string.len(body_str))
		--{bring out all the <state> fields in a table}
		local statearray = {}
		for capture in string.gmatch(body_str, "<[%a%d-].-:State (.-)</[%a%d-]*:State>") do
			table.insert(statearray, capture)
		end
		debug(pinfo.number, "Number of -state- entries found in WaveformReport: ", #statearray)
		local ipfestatearray = {}
		local ipfestatearray_adv = {}
		local descriptorhandle, determinationtime, stateversion, validity, samples
		local samples		--> string, space separated values
		local samplestable = {}
		for i = 1, #statearray do
			--descriptorhandle = string.match( statearray[i], 'DescriptorHandle="([%a%d-]+)"')
			descriptorhandle = string.match( statearray[i], 'DescriptorHandle="([^"]+)')
			determinationtime = string.match( statearray[i], 'DeterminationTime="([%d-]+)"')
			stateversion = string.match( statearray[i], 'StateVersion="([%d-]+)"')
			validity = string.match( statearray[i], 'Validity="([%a-]+)"')
			samples = string.match( statearray[i], 'Samples="(.-)"')
			if samples == nil or samples == '' then
				samples = 'na'
			end	
			if validity == nil or validity == '' then
				validity = 'na'
			end	
			if determinationtime == nil or determinationtime == '' then
				determinationtime = 'na'
			end	
			--debug(pinfo.number,i .. " / " .. descriptorhandle, stateversion .. samples .. validity .. determinationtime) 
			ipfestatearray[descriptorhandle] = {determinationtime, stateversion, validity, samples}
			ipfestatearray_adv[descriptorhandle] = {determintime=determinationtime, statever=stateversion, valid=validity, samplesset=samples}
		end
		
		--Sort and then insert all Ipfe entries and info into subtree
		local tkeys = {}
		local determinetime_human_readable
		-- populate the table that holds the keys
		for k in pairs(ipfestatearray_adv) do 
			table.insert(tkeys, k) 
		end
		-- sort the keys
		table.sort(tkeys)
		-- use the keys to retrieve the values in the sorted order
		for _, k in ipairs(tkeys) do 
			--Table key sorted, so use to access table holding system data we are looking for
			j = ipfestatearray_adv[k]
			local ipfetree = waveformstree2:add(pf.IpfeDevice, k)
			ipfetree:add(pf.DescriptorHandle, k)
			ipfetree:add(pf.DeterminationTime, j.determintime)
			if j.determintime == 'na' then
				determinetime_human_readable = 'na'
			else
				determinetime_human_readable = os.date('%Y-%m-%d %H:%M:%S',j.determintime/1000)
			end
			ipfetree:add(pf.DeterminationTimeHR, determinetime_human_readable)
			ipfetree:add(pf.StateVersion, j.statever)
			ipfetree:add(pf.Validity, j.valid)
			ipfetree:add(pf.Samples, j.samplesset)			
		end
		
		
		
		tkeys = {}
		-- populate the table that holds the keys
		for k in pairs(ipfestatearray) do 
			table.insert(tkeys, k) 
		end
		-- sort the keys
		table.sort(tkeys)
		-- use the keys to retrieve the values in the sorted order
		for _, k in ipairs(tkeys) do 
			debug(pinfo.number,k , table.concat(ipfestatearray[k], ", ")) 
			
			--determine field based on Ipfe Name, e.g. k is Ipfe0-16 from the xml data stream but the field is Ipfe0_16
			if k == "Ipfe0-33" then
				local waveformstree = subtree:add("IEEE11073 Ipfe0-33")
				debug(pinfo.number, "We have an Ipfe0-33 match", '') 
				waveformstree:add(pf.Ipfe0_33_DescriptorHandle, k)
				waveformstree:add(pf.Ipfe0_33_DeterminationTime, ipfestatearray[k][1])
				waveformstree:add(pf.Ipfe0_33_DeterminationTimeHR, os.date('%Y-%m-%d %H:%M:%S',(ipfestatearray[k][1])/1000))
				waveformstree:add(pf.Ipfe0_33_StateVersion, ipfestatearray[k][2])
				waveformstree:add(pf.Ipfe0_33_Validity, ipfestatearray[k][3])
				waveformstree:add(pf.Ipfe0_33_Samples, ipfestatearray[k][4])
			
				--Insert into Ipfe0-33 time for timing analysis if this one is not present
				if next(Ipfe33_time) == nil then
					debug(pinfo.number, "gtiming table was empty, adding state", ipfestatearray[k][2]) 
					table.insert(Ipfe33_time, {ipfestatearray[k][2], ipfestatearray[k][1]}) 
				end
				--Check gtiming table so we don't do multiple inserts
				local oldentry = 0
				for index, state_dtime in ipairs(Ipfe33_time) do
					debug(pinfo.number, "gtiming table not empty, compare table to current:", index .. "/".. state_dtime[1] .. " to " .. ipfestatearray[k][2]) 
					if state_dtime[1] == ipfestatearray[k][2] then 
						debug(pinfo.number, " --> gtiming entry match... skipping: ", index .. "/".. state_dtime[1] .. " to " .. ipfestatearray[k][2])
						oldentry = 1						
						break
					end	
				end
				if oldentry == 0 then 
					debug(pinfo.number, "-->gtiming no match ... adding state version: ",  ipfestatearray[k][2])					
					table.insert(Ipfe33_time, {ipfestatearray[k][2], ipfestatearray[k][1]}) 
				end
				for index, state_dtime in ipairs(Ipfe33_time) do 
					debug(pinfo.number, "Summary gtiming table index: " .. index, state_dtime[1] .. " / " .. state_dtime[2]) 
				end
				
				--Calculate our specific state version DeterminationTime against the first reference identified here
				local globalmin = table_min_statever(Ipfe33_time)
				local timetofirst = tonumber(ipfestatearray[k][1]) - globalmin[2]
				debug(pinfo.number, "Min state and dtime: ", globalmin[1] .. ' / ' .. globalmin[2])
				waveformstree:add(pf.Ipfe0_33_DTime_sinceFirst, timetofirst)
				
				--Calculate our specific state version DeterminationTime against the last report received
				
				local previousvalue = find_previous_statever(pinfo.number, Ipfe33_time, tonumber(ipfestatearray[k][2]))
				debug(pinfo.number, "Compare state: " .. tonumber(ipfestatearray[k][2]),  " to State:" .. previousvalue[1] .. "  dTime: " ..  previousvalue[2])
				local timesincelast = tonumber(ipfestatearray[k][1]) - previousvalue[2]
				debug(pinfo.number, "timesincelast: ", timesincelast .. " with type: " .. type(timesincelast))
				waveformstree:add(pf.Ipfe0_33_DTime_sinceLast, timesincelast)
			end	
		end
	end	
end


-- Step 6 - register the new protocol as a postdissector
register_postdissector(IEEE11073_p)








