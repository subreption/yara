
// KW: A module to facilitate the signsrch "AND" concept
// Match all passed values in the vicinity of the "first" match with in a specified range.
// To update this code in a libyara build, touch "modules.c"
// TODO: Developed in Windows only but with other OSes in mind
//       but not tested for libyara multi-platform computability.
#include <yara/modules.h>

#define MODULE_NAME area

// modules.h return_integer() macro but with error code for failure handling
#define return_integer_error(_error)                                       \
  {                                                                        \
    assertf(                                                               \
        __function_obj->return_obj->type == OBJECT_TYPE_INTEGER,           \
        "return type differs from function declaration");                  \
    yr_object_set_integer(YR_UNDEFINED, __function_obj->return_obj, NULL); \
    return (int) _error;                                                   \
  }

// To track the Yara scan buffer
static uint8_t *scan_data = NULL;
static size_t scan_size = 0;

/*
Method: Look for a series of 32bit or 64bit values within a specified +-range of the first value in the series.

Arguments:
first_offset: Offset into scan buffer from the first of the sequence match value.
value_bits: Value size. Either 32 or 64 bits are supported.
value_count: Count of values (including the first matched one).
scan_range: Range to scan up to plus or minus from the 'first_offset' offset.
hex_data: The values as an encoded binary string. Since Yara "modules" currently doesn't support variable
          arguments, this is the only way we can get the input we need currently.

Returns: 1 if match, else 0.

Intended to be used with rules in a specific way.
Example:
We are looking for these five 32bit values within 640 of the first value match to
a potential "Data Encryption Standard" (DES) initialize function.
0x0F0F0F0F 0x0000FFFF 0x33333333 0x00FF00FF 0x55555555
Ref: https://www.oryx-embedded.com/doc/des_8c_source.html

A rule to utilize our area module is:
rule DES_INIT
{
	meta:
		description = "A DES init function"
	strings:
		$first = { 0F 0F 0F 0F }
	condition:
		$first and area.scan(@first, 32, 5, 640, "\xFF\xFF\x00\x00\x33\x33\x33\x33\xFF\x00\xFF\x00\x55\x55\x55\x55")
}

Yara will first try to match the 0x0F0F0F0F value as a byte sequence from the conditional "$first" part.
If match found, the area module will scan from the match address minus 640 bytes, to match address
plus 640 bytes for the four reminding four 32bit values (passed in as the hex string).
*/
define_function(scan)
{    
    uint64_t *matches = NULL;

    #ifdef _WIN32
	__try
    #endif
	{
        uint64_t first_offset = integer_argument(1);
        uint64_t value_bits   = integer_argument(2);
        uint64_t value_count  = integer_argument(3);
        uint64_t scan_range   = integer_argument(4);
        char *hex_data = string_argument(5);
        if (!hex_data)
            return_integer_error(ERROR_INVALID_ARGUMENT);

        // Only 32bit or 64bit area values are currently supported
        size_t value_size = (value_bits / 8);
        if (!((value_size == (32 / 8)) || (value_size == (64 / 8))))
            return_integer_error(ERROR_INVALID_ARGUMENT);
       
        if (!value_count || (scan_range < (value_size * value_count)))
            return_integer_error(ERROR_INVALID_ARGUMENT);

        // Matching addresses tracking array 
        uint64_t match_count = 1;        
        #pragma warning(disable:4312) /* For erroneous: "warning C4312: 'type cast': conversion from 'int' to 'uint64_t *' of greater size" */
        matches = (uint64_t *) yr_calloc((size_t) value_count, (size_t) sizeof(uint64_t));
        #pragma warning(default:4312)
        if (!matches)
            return_integer_error(ERROR_INSUFFICIENT_MEMORY);

        // Save first/matched value address
        matches[0] = ((uint64_t) scan_data + first_offset);

        // =======================================================================
        // Simple by vale byte scanning. 
        // Could be faster but adequate since the scan range is small for the normative case, 
        // plus the count of area scans are typically small (5% of the total rules) also.
        size_t start_offset;
        if (first_offset < scan_range)
            start_offset = 0;
        else
            start_offset = (first_offset - scan_range);

        size_t end_offset = (first_offset + scan_range);
        size_t scan_size_adj = (scan_size - value_size);        
        if (end_offset > scan_size_adj)
            end_offset = scan_size_adj;

        size_t scan_length = (end_offset - start_offset);
        if (scan_length < (value_count * value_size))
        {
            // Corner case where the scan length is smaller than the area value length
            return_integer(0);
        }

        if (value_bits == 32)
        {           
            // Iterate through the input value set
            uint32_t *values = (uint32_t*) hex_data;
            size_t count = value_count;
            for (size_t i = 0; i < count; i++)
            {
                uint32_t value = *values++;                
                uint8_t *data = (scan_data + start_offset);

                // Iterate though the scan range by bytes
                for (size_t j = 0; j < scan_length; j++, data++)
                {
                    uint32_t test = *((uint32_t*) data);
                    if(test == value)
                    {
                        // Skip if we've already matched this value (for when one or more of the value set are the same)
                        uint64_t match_addr = (uint64_t) data;
                        for (size_t k = 0; k < match_count; k++)
                        {
                            // Already known
                            if (matches[k] == match_addr)
                                goto continue_scan;
                        }

                        // Got a match for this value                      
                        matches[match_count++] = match_addr;
                        break;
                    }

                    continue_scan:;
                }
            }
        }
        else
        // 64bit value version
        {            
            uint64_t *values = (uint64_t *) hex_data;            
            size_t count = value_count;
            for (size_t i = 0; i < count; i++)
            {
                uint64_t value = *values++;
                uint8_t *data = (scan_data + start_offset);
               
                for (size_t j = 0; j < scan_length; j++, data++)
                {
                    uint64_t test = *((uint64_t*) data);
                    if(test == value)
                    {                        
                        uint64_t match_addr = (uint64_t) data;
                        for (size_t k = 0; k < match_count; k++)
                        {
                            if (matches[k] == match_addr)
                                goto continue_scan2;
                        }
                       
                        matches[match_count++] = match_addr;
                        break;
                    }

                    continue_scan2:;
                }
            }
        }

		yr_free(matches);
        matches = NULL;      
		return_integer(match_count >= value_count);
	}
    #ifdef _WIN32
	__except (TRUE) 
    {
		yr_free(matches);
		matches = NULL;
		return_integer_error(ERROR_INTERNAL_FATAL_ERROR);
    }
    #endif
}

begin_declarations
    declare_function("scan", "iiiis", "i", scan);
end_declarations;


int module_initialize(YR_MODULE *module)
{
    return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE *module)
{
    return ERROR_SUCCESS;
}


int module_load(YR_SCAN_CONTEXT *context, YR_OBJECT *module_object, void *module_data, size_t module_data_size)
{
    // Track this scan buffer space:
    // This will be called on every new scan with a rule set that has a 'import "area"' in it.
    // TODO: For the Yara4Ida project we scan per memory segment only, thus have only a single buffer at a time.
    //  For the general Yara use case we'd probably want to track the YR_MEMORY_BLOCK, and our 'scan' 
    //  function would need to figure out what block it's in based on the @find offset, etc.
    YR_MEMORY_BLOCK *block = first_memory_block(context);
    scan_data = block->fetch_data(block);
    scan_size = block->size;

    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT *module_object)
{
    scan_data = NULL;
    scan_size = 0;

    return ERROR_SUCCESS;
}
