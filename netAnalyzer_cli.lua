-- netAnalyzer_cli.lua
-- https://wiki.wireshark.org/uploads/5480731fd0e9a6da06fb9616cceb80c7/220701_sf22us_duct_tape_as_presented.pdf
-- Sample capture: httptest.pcapng
-- Check out: 	https://wiki.wireshark.org/Lua/Examples#extract-field-values
--				https://wiki.wireshark.org/Lua/Examples/PostDissector
--				https://ask.wireshark.org/question/16067/80211-lua-dissector/
--				http://alex-ii.github.io/tech/2018/05/08/dissector_for_Wireshark_udp.html
--				https://wiki.wireshark.org/Lua/Dissectors
--
-- CLI single pass version
--	Once we see a trigger, push to trigger table
--	Replace next tiome we see a trigger
--	Versions
--	0.0.2	CLI variant for one pass filtering
--	0.0.3	Change protocol name so GUI version and CLI can be run at same time
--			Add debug line for better filtering / csv format to import into tools such as minitab	
--	0.0.4	Reimplement as tap/listener
--	0.0.5	Add camera timing
--	0.0.6a	Add SDC protocol support - analyze waveform data when using SDC with 0.0.3 version of ieee11073.lua
	
	

-- Step 1 - document as you go. See header above and set_plugin_info().

local netAnalyzerPDScli_info =
{
	version = "0.0.4",
	author = "G. Cragg",
	description = "Hilscher netAnalyzer to PDS calculator for tshark/cli",
	repository = "Nowhere"
}
set_plugin_info(netAnalyzerPDScli_info)

--Config DEBUG - will print values.  Set to true or false.
-- DEBUG = false | true
local DEBUG = true
--local DEBUG = false

--Minitab-friendly output
--local minitaboutput = false
local minitaboutput = true

--Timezone adjustment - wireshark times are internally UTC but we want to output data in local time
--Example: EDT is (hours) UTC-4
--local timezone = -4
local timezone = -4



--Define waveform values to detect when our external impulse from the Prosim is present
local inrange_match_low = 300
local inrange_match_high = 1000

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
		print(" netAnalyzer [" ..frameid.. "] " .. text .. " " .. str)
	end
end

--Find inrange of test value from table
local function find_inrange_array(frameid, table, lowrange, highrange)
	--table in will be {}
	--Out result will 1 or0 - is there a value between the low and hogh range
	--e.g. array={ 1 2 3 4 5 6 7 8 9 1000 1001 10002 10003 45 50 55 60 45 }
		--max_array(frameid,array, 100, 200) --> false
		--max_array(frameid,array, 50, 60) --> true
	local i,j
	for i,j in ipairs(table) do
		debug(frameid, "Checking in range sample " .. i ..": ", lowrange .. " < " .. j .. " < " .. highrange)
		if ( tonumber(j) >= lowrange and tonumber(j) <= highrange ) then
			debug(frameid, "Inrange match found ", lowrange .. " < " .. j .. " < " .. highrange) 
			return 1
		end
	end	
	return 0
end

--Find previous GPIO edge entry given a Waveform spike packet
local function find_previous_trigger(frameid, table, waveform_change_time)
	--table in will be {} and is expected to be GPIO0_time table
	--Out result will be the GPIO0 time preceding the waveform_change_time
	--Start at beginning of table and step through, comparing GPIO trigger time to waveform_change_time
	--if wvfm time is > greater than trigger time, ad to temp table.  Answer is then max or last entry of temp table
	
	local i
	local temp_table = {}
	for i=1, #table, 1 do
		if ( waveform_change_time >= table[i] ) then
			debug(frameid, "waveform_change_time is newer than GPIO", waveform_change_time .. " > " .. table[i] ) 
			--table.insert(temp_table, table[i])
			temp_table[i] = table[i]
		end
	end	
	return temp_table[#temp_table]
end

--Split string into a table - SDC waveforms are a string of a individual values seperated by a space
local function split(inputstr, sep) 
	sep=sep or '%s' 
	local t={}  
	for field,s in string.gmatch(inputstr, "([^"..sep.."]*)("..sep.."?)") do 
		table.insert(t,field)  
		if s=="" then 
			return t 
		end 
	end 
end



-- Step 2 - create a protocol to attach new fields to
-- this is our tap
local tap = Listener.new();

--Global variables that make up timing
testtrigger = {}						--> GPIO0 trigger entries - running table
RT_PWS_Calculated = false		--> If wfm impulse crosses multiple pkts, use only first
RT_PDS_Calculated = false		--> If wfm impulse crosses multiple pkts, use only first
gpio1_calculated = false		--> If wfm impulse crosses multiple pkts, use only first
gpio2_calculated = false		--> If wfm impulse crosses multiple pkts, use only first
glblresults = {}			--> Table of results, indexed by trigger packet number

-- Step 3 - add some field(s) to Step 2 protocol


-- Step 4 - create a Field extractor to copy packet field data.
local ip_target_f = Field.new("ip.dst")
local ip_source_f = Field.new("ip.src")
local frame_no_f = Field.new("frame.number")
local frame_time_f = Field.new("frame.time_epoch")
local number_ndos_f = Field.new("ndo.number_8")
local number_wvfs_f = Field.new("ndo.pds_wvf_hdr_num_waveforms")
local udp_payload_f = Field.new("udp.payload")
local ndo_id_f = Field.new("ndo.id")
local gpio_number_f = Field.new("netanalyzer.gpio_event.gpio_number")
local ndocr_f = Field.new("ndocr.insaenr")
local pws_wvfm_sample_f = Field.new("ndo.pws_wvf_pws_wvf_data")
local pds_wvfm_sample_f = Field.new("ndo.pds_wvf_wvf_data_sample_value")
local IEEE11073_sdc_service_f = Field.new("IEEE11073.sdc_service")
local IEEE11073_sdc_report_type_f = Field.new("IEEE11073.sdc_report_type")



--SDC specific fields
local ipfe033_wvfm_sample_f = Field.new("IEEE11073.Waveforms.Ipfe0-33.Samples")

--Some local counter variables.  ToDo: clean these up
local k, v, i, j

-- Step 5 - create the postdissector function that will run on each frame/packet
function tap.packet(pinfo,tvbbuffer)
	
	--debug(pinfo.number, "Dissector tvb captured length", tvbbuffer:captured_len())
	
	--Check for Hilscher netAnalyzer frames
	--netANALYZER (GPIO event)
		--GPIO event
		--GPIO event on: GPIO 0 (0x00)
		--GPIO event type: Rising edge (0x00) GPIO event on GPIO 0 (rising edge)
	--Configure as Rising edge, so GPIO event type should be 0x00 always
	--Collect which GPIO event via netanalyzer.gpio_event.gpio_number
	--Test should always be GPIO0 --> GPIO1 --> GPIO2 --> GPIO3, so make sure it is configured this way (physically)


	for k, v in pairs({ gpio_number_f() }) do
		-- process data and add results to the tree
		if v.name ~= "" and v.name ~= nil  then
			debug(pinfo.number, "Frame detected gpio_number .display / .value: ", v.display .." / " .. v.value)

			--If GPIO0 is set (value = 0) then we have the start of a new timing sequence
			if v.value == 0 then
				debug(pinfo.number, "GPIO0 event detected start timing sequence: ", pinfo.abs_ts)
				table.remove(testtrigger,1)
				table.insert(testtrigger,{pktnumber = pinfo.number, timestamp = pinfo.abs_ts})
				debug(pinfo.number, "testtrigger pktnumber and triggertime ", testtrigger[1].pktnumber .. ", " ..testtrigger[1].timestamp) 
				RT_PWS_Calculated = false
				RT_PDS_Calculated = false
				gpio1_calculated = false
				gpio2_calculated = false
				--Insert entry for globalresults table
				glblresults[testtrigger[1].pktnumber] = {triggertime=testtrigger[1].timestamp, triggernumber=testtrigger[1].pktnumber, pwspktno='na', RT_PWS='na', pdspktno='na', RT_PDS='na', gpio1pktno='na', RT_GPIO1='na', gpio2pktno='na', RT_GPIO2='na'}
			--If GPIO0 is set (value = 0) then we have the start of a new timing sequence
			elseif v.value == 1 and not gpio1_calculated then
				debug(pinfo.number, "GPIO1 event detected at time: ", pinfo.abs_ts)	
				if testtrigger[1].pktnumber > 0 then
					glblresults[testtrigger[1].pktnumber].gpio1pktno = pinfo.number 
					glblresults[testtrigger[1].pktnumber].RT_GPIO1 = pinfo.abs_ts - testtrigger[1].timestamp
					gpio1_calculated = true
				else		--> handle case where we did not see a start of test trigger, so skip this one
					debug(pinfo.number, "No start of test trigger ", "... skipping")
					return
				end
			elseif v.value == 2 and not gpio2_calculated then
				debug(pinfo.number, "GPIO2 event detected at time: ", pinfo.abs_ts)	
				if testtrigger[1].pktnumber > 0 then
					glblresults[testtrigger[1].pktnumber].gpio2pktno = pinfo.number 
					glblresults[testtrigger[1].pktnumber].RT_GPIO2 = pinfo.abs_ts - testtrigger[1].timestamp
					gpio2_calculated = true
				else		--> handle case where we did not see a start of test trigger, so skip this one
					debug(pinfo.number, "No start of test trigger ", "... skipping")
					return
				end
			else
				debug(pinfo.number, "Unknown GPIO value received ", "... skipping")
				return
			end
			for i,j in pairs(glblresults) do
				debug(pinfo.number, "Global results: ", i .. "," .. j.triggertime .. "," .. j.pwspktno .. "," .. j.RT_PWS .. "," .. j.pdspktno .. "," .. j.RT_PDS .. "," .. j.gpio1pktno .. "," .. j.RT_GPIO1 .. "," .. j.gpio2pktno .. "," .. j.RT_GPIO2) 
			end	
			return
		end
	end

	--Check for SDC TLS/HTTP/XML/WaveformStream (?)
	--Check for PDS udp.port == 2050
	--Check for PWS udp.port == 18000
	--ToDo: Check for M300 LLIP tcp.port == 18000
	
	
	local NDO_sizes = {}				--> NDOs contained in this packet
	local NDO_types = {}				--> NDOs contained in this packet
	
	local ndos_total_number
	local ndos_total_wvfms
	local tvbsbuf						-->Actual buffer of data, could be plain text or decrypted plaintext
	local response_time_calc
	local last_trigger_time
	local inrange_match
	local wvfrm_samples = {}
	
	---------------------------------------------------------------------------
	--Check for SDC protocol
	local sdc_service = ''
	local sdc_report = ''
	local sdc_wavfms_string = ''
	local sdc_wavfms_table = {}
	local k,v, i, j, m, n

	for k, v in pairs({ IEEE11073_sdc_service_f() }) do
		sdc_service = v.display
		if sdc_service == 'WaveformService' then
			for i, j in pairs({ IEEE11073_sdc_report_type_f() }) do
				sdc_report = j.display 
				debug(pinfo.number, "Frame detected for SDC - service/report: " ..sdc_service, sdc_report)
				if sdc_report == "WaveformStream" then
					for m, n in pairs({ ipfe033_wvfm_sample_f() }) do		--SDC waveforms 
						debug(pinfo.number, "SDC Waveform samples string: ", n.value)
						sdc_wavfms_table = split(n.value)
						for q, r in ipairs( sdc_wavfms_table ) do
							local s = string.format(" [%2d] % 3f", q, r)
							debug(pinfo.number, s , '')
						end
						inrange_match = find_inrange_array(pinfo.number, sdc_wavfms_table, inrange_match_low/1000, inrange_match_high/1000)
						debug(pinfo.number, "No. of waveform samples  / inrange_match result: ", #sdc_wavfms_table .. " / " .. inrange_match)
						
						if (inrange_match == 1 and #testtrigger > 0 and not RT_PWS_Calculated) then
							debug(pinfo.number, "Calculating RT_PWS, my packet time: ", pinfo.abs_ts)
							--last_trigger_time = find_previous_trigger(pinfo.number, testtrigger, pinfo.abs_ts)
							last_trigger_time = testtrigger[1].timestamp
							debug(pinfo.number, "triggertime: ", last_trigger_time)
							response_time_calc = pinfo.abs_ts - last_trigger_time
						end	

						if response_time_calc ~= nil then
							debug(pinfo.number, "Response time RT_PWS: ", response_time_calc)
							RT_PWS_Calculated = true
							debug(pinfo.number, "RT Calculated PWS/PDS:", tostring(RT_PWS_Calculated) .. " " .. tostring(RT_PDS_Calculated))
							glblresults[testtrigger[1].pktnumber].pwspktno = pinfo.number
							glblresults[testtrigger[1].pktnumber].RT_PWS = response_time_calc
						end
						return		
					end	
				end
			end	
		end	
	end
	
	
	---------------------------------------------------------------------------
	--Check for PDS or PWS, bail out if neither present
	if pinfo.dst_port ~= 2050 and pinfo.dst_port ~= 18000  then
		debug(pinfo.number, "Not a netAnalyzer, PDS/PWS packet, or SDC packet", 'bye')
		return
	end	
	
	---------------------------------------------------------------------------
	--Check for PDS or PWS, bail out if neither present
	if pinfo.dst_port == 18000 then
		debug(pinfo.number, "Frame detected: ", "possible PWS")
		for k, v in pairs({ pws_wvfm_sample_f() }) do
			table.insert(wvfrm_samples, v.value)
		end
		inrange_match = find_inrange_array(pinfo.number, wvfrm_samples, inrange_match_low, inrange_match_high)
		debug(pinfo.number, "No. of waveform samples  / inrange_match result: ", #wvfrm_samples .. " / " .. inrange_match)
		
		if (inrange_match == 1 and #testtrigger > 0 and not RT_PWS_Calculated) then
			debug(pinfo.number, "Calculating RT_PWS, my packet time: ", pinfo.abs_ts)
			--last_trigger_time = find_previous_trigger(pinfo.number, testtrigger, pinfo.abs_ts)
			last_trigger_time = testtrigger[1].timestamp
			debug(pinfo.number, "triggertime: ", last_trigger_time)
			response_time_calc = pinfo.abs_ts - last_trigger_time
		end	

		if response_time_calc ~= nil then
			debug(pinfo.number, "Response time RT_PWS: ", response_time_calc)
			RT_PWS_Calculated = true
			debug(pinfo.number, "RT Calculated PWS/PDS:", tostring(RT_PWS_Calculated) .. " " .. tostring(RT_PDS_Calculated))
			glblresults[testtrigger[1].pktnumber].pwspktno = pinfo.number
			glblresults[testtrigger[1].pktnumber].RT_PWS = response_time_calc
		end
		return		
	end
		 	
	
	----------------------------------------------------------
	if pinfo.dst_port == 2050 then
		debug(pinfo.number, "Frame detected: ", "possible PDS")	
		
		local ndos_contained_in_pkt = {}
		local is_waveform_pkt = "No"
	
		for k, v in pairs({ ndo_id_f() }) do
			debug(pinfo.number, "ndo_id .display: ", v.display)
			table.insert(ndos_contained_in_pkt,v.display)
		end
		for k, v in pairs(ndos_contained_in_pkt) do
			if v == "NDO_PDS_WAVEFORM (0x000c)" or v == "NDO_LLIP_PWS (0x008d)" then
				is_waveform_pkt = "Yes"
			end
		end
		--debug(pinfo.number, "is_waveform_pkt: ", is_waveform_pkt)
		
		for k, v in pairs({ pds_wvfm_sample_f() }) do
			table.insert(wvfrm_samples, v.value)
		end
		inrange_match = find_inrange_array(pinfo.number, wvfrm_samples, inrange_match_low, inrange_match_high)
		debug(pinfo.number, "No. of waveform samples/inrange_match result: ", #wvfrm_samples .. " / " .. inrange_match)
	
		if (inrange_match == 1 and #testtrigger > 0 and not RT_PDS_Calculated) then
			debug(pinfo.number, "Calculating RT_PDS, my packet time: ", pinfo.abs_ts)
			--last_trigger_time = find_previous_trigger(pinfo.number, testtrigger, pinfo.abs_ts)
			last_trigger_time = testtrigger[1].timestamp
			debug(pinfo.number, "triggertime: ", last_trigger_time)
			response_time_calc = pinfo.abs_ts - last_trigger_time
		end	

		if response_time_calc ~= nil then
			debug(pinfo.number, "Response time RT_PWS: ", response_time_calc)
			RT_PWS_Calculated = true
			debug(pinfo.number, "RT Calculated PWS/PDS:", tostring(RT_PWS_Calculated) .. " " .. tostring(RT_PDS_Calculated))
			glblresults[testtrigger[1].pktnumber].pdspktno = pinfo.number
			glblresults[testtrigger[1].pktnumber].RT_PDS = response_time_calc
		end
		return		
	end
	
	---------------------------------------------------------
	--Check for SDC protocol
	
	for k, v in pairs({ ipfe033_wvfm_sample_f() }) do
		-- process data and add results to the tree
		if v.name ~= "" and v.name ~= nil  then
			debug(pinfo.number, "Frame detected for SDC Waveforms .display / .value: ", v.display .." / " .. v.value)
		end
	end	
end



function tap.draw()

	--sort GlbResults table
	local tkeys = {}
	-- populate the table that holds the keys
	for k in pairs(glblresults) do 
		table.insert(tkeys, k) 
	end
	-- sort the keys
	table.sort(tkeys)
	-- use the keys to retrieve the values in the sorted order
	local i = 0

	if not minitaboutput then
		print("Counter, TriggerPktNo, triggertime, PWSpktno, RT_PWS[sec], PDSpktno, RT_PDS[sec], GPIO1pktno, RT_GPIO1[sec], GPIO2pktno, RT_GPIO2[sec],")
		for _, k in ipairs(tkeys) do 
			j = glblresults[k]
			--test results - if both RT are zero, then we don't have any measurement.  This can happen, for example, with secure mode
			--on Infinity - can't decrypt until we get a NameService, so could have multiple tests but data is encrypted until
			--DRNS arrives
			--if ( j.RT_PWS < 0.0001 and j.RT_PDS < 0.0001 and j.RT_GPIO1 < 0.001 ) then goto continue end
			if ( j.RT_PWS == 'na' and j.RT_PDS == 'na' and j.RT_GPIO1 == 'na' ) then goto continue end
			--print(i .. "," .. k .. "," .. j.triggertime .. "," .. j.pwspktno .. "," .. j.RT_PWS .. "," .. j.pdspktno .. "," .. j.RT_PDS)
			print(i .. "," .. k .. "," .. j.triggertime .. "," .. j.pwspktno .. "," .. j.RT_PWS .. "," .. j.pdspktno .. "," .. j.RT_PDS .. "," .. j.gpio1pktno .. "," .. j.RT_GPIO1 .. "," .. j.gpio2pktno .. "," .. j.RT_GPIO2) 
			i = i + 1
			::continue::
		end	
	end
	
	if minitaboutput then
		--print("------Start of Minitab-friendly output------")
		print("TestCounter, MeasuredParameter, ParameterValue, AltParameterValue, TriggerTimestamp, TriggerExcelTimestamp, TriggerElapsedTime[sec]")
		local firsttrigger = true
		local basetime = 0
		i = 0
		for _, k in ipairs(tkeys) do 
			--assign array row pof data values
			j = glblresults[k]
			
			--Check if data is 'bad' - incomplete enough that we want to skip this data point
			if ( j.RT_PWS == 'na' and j.RT_PDS == 'na' and j.RT_GPIO1 == 'na' ) then goto continue end
			
			--configure timestamp and other time info
			exceltime = j.triggertime/86400 + 25569 + timezone/24
			if firsttrigger then
				basetime = exceltime
				firsttrigger = false
			end
			elapsedtime = (exceltime - basetime)*24*60*60
			
			--output data in Minitab-friendly output
			print(i .. ", TriggerPktNo,, "       .. k             .. ", "  .. os.date("%c", j.triggertime) .. ",,")
			print(i .. ", SampleTriggerTime,, "  .. j.triggertime .. ", "  .. os.date("%c", j.triggertime) .. ",,")
			print(i .. ", PWSpktno,, "           .. j.pwspktno    .. ", "  .. os.date("%c", j.triggertime) .. ",,")
			print(i .. ", RT_PWS[sec], "         .. j.RT_PWS      .. ",, " .. os.date("%c", j.triggertime) .. ", " .. exceltime .. ", " .. elapsedtime)
			print(i .. ", PDSpktno,, "           .. j.pdspktno    .. ", "  .. os.date("%c", j.triggertime) .. ",,")
			print(i .. ", RT_PDS[sec], "         .. j.RT_PDS      .. ",, " .. os.date("%c", j.triggertime) .. ", " .. exceltime .. ", " .. elapsedtime)
			print(i .. ", GPIO1pktno,, "         .. j.gpio1pktno  .. ", "  .. os.date("%c", j.triggertime) .. ",,")
			print(i .. ", RT_GPIO1[sec], "       .. j.RT_GPIO1    .. ",, " .. os.date("%c", j.triggertime) .. ", " .. exceltime .. ", " .. elapsedtime)
			print(i .. ", GPIO2pktno,, "         .. j.gpio2pktno  .. ", "  .. os.date("%c", j.triggertime) .. ",,")
			print(i .. ", RT_GPIO2[sec], "       .. j.RT_GPIO2    .. ",, " .. os.date("%c", j.triggertime) .. ", " .. exceltime .. ", " .. elapsedtime)
			i = i + 1
			::continue::
		end			
	end
end

---->-------------------------------------------------------------------------------------------------->--
--Debug FieldInfo information
--debug(pinfo.number, "Frame detected gpio_number .display / value: ", v.display .." / " .. v.value)
--debug(pinfo.number, "gpio_number .value: ", v.value)
--debug(pinfo.number, "gpio_edge0 .label: ", v.label)
--debug(pinfo.number, "gpio_edge0 .type: ", v.type)
--debug(pinfo.number, "gpio_edge0 .name: ", v.name)




--for i in $(ls *.pcap); do echo ${i}; tshark -q -r ${i} -X lua_script:netAnalyzer_cli.lua -C PDS | tee ${i}.csv; done; date
--tshark -q -r M540_XG8_Secure_2023-05-02_subset1.pcap -X lua_script:netAnalyzer_cli.lua -C PDS | tee M540_XG8_Secure_2023-05-02_subset1.csv 

--tshark -q -r camera1_subset2.pcap -X lua_script:netAnalyzer_cli.lua -C PDS

--for i in $(ls {*.pcap,*.pcapng} 2>/dev/null); do echo "File: " ${i} " started at: " $(date); tshark -q -r ${i} -X lua_script:netAnalyzer_cli.lua -C PDS | tee ${i}.csv; done;

	