// DuplicateFileFindTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <cstdint>

#include <iostream>
#include <iomanip>
#include <fstream>

#include <filesystem>

#include <thread>
#include <future>
#include <functional>
#include <chrono>


#include <string>
#include <vector>
#include <queue>
#include <map>

#include <wolfssl\wolfcrypt\hash.h>

#include <hex.h>

using namespace std;
using namespace std::tr2::sys;

typedef list<pair<uintmax_t, wstring>> _list_pair_ui_str;
typedef list<pair<wstring, wstring>> _list_pair_str_str;
typedef multimap<uintmax_t, wstring> _multimap_ui_str;
typedef multimap<const uintmax_t, wstring> _multimap_cui_str;

typedef map<uintmax_t, wstring> _map_ui_str;
typedef map<const uintmax_t, wstring> _map_cui_str;

typedef map<wstring, uintmax_t> _map_str_ui;

typedef vector<wstring> _vector_str;

#define _make_ui_str_pair make_pair<uintmax_t, wstring>
#define _make_cui_str_pair make_pair<const uintmax_t, wstring>

#define _make_str_ui_pair make_pair<wstring, uintmax_t>
#define _make_str_cui_pair make_pair<wstring, const uintmax_t>

#define _make_str_str_pair make_pair<wstring,wstring>

//structs
typedef struct _directory_contents
{
	//default constructor
	explicit _directory_contents()
	{}

	~_directory_contents()
	{}

	//copy constructor
	_directory_contents(const _directory_contents& rhs) : m_list_pair_ui_str(rhs.m_list_pair_ui_str), m_vector_str(rhs.m_vector_str)
	{}

	//move constructor
	_directory_contents(_directory_contents&& rhs) noexcept
		: m_list_pair_ui_str(std::move(rhs.m_list_pair_ui_str)), m_vector_str(std::move(rhs.m_vector_str))
	{}

	//assignment operator
	_directory_contents& operator=(_directory_contents&& rhs)
	{
		m_list_pair_ui_str = move(rhs.m_list_pair_ui_str);
		m_vector_str = move(rhs.m_vector_str);
		return *this;
	}

	_list_pair_ui_str m_list_pair_ui_str;
	_vector_str m_vector_str;

private:
	//get memory location
	void outputMemberMemoryLocation()
	{
		cout << " m_multimap_ui_str: " << "0x" << hex << noshowbase << setw(2) << setfill('0') << &m_list_pair_ui_str;
		cout << " m_vector_str: " << "0x" << hex << noshowbase << setw(2) << setfill('0') << &m_vector_str;
		cout << " ... container thread id: " << this_thread::get_id() << endl;
	}

}directory_contents;

//file system object
typedef struct _fso_information
{
	//default constructor
	explicit _fso_information(){}

	_fso_information(std::wstring wstrfsoname, 
		             std::experimental::filesystem::file_type filetype = std::experimental::filesystem::file_type::unknown, 
		             unsigned int uifsosize = 0,
		             wc_HashType hashtype = wc_HashType::WC_HASH_TYPE_NONE,
		             std::wstring wstrhash = L"" )
	{
		m_wstr_fso_name = wstrfsoname;
		m_fso_type = filetype;
		m_ui_fso_size = uifsosize;
		m_wc_hash_type = hashtype;
		m_wstr_fso_hash = wstrhash;
	}


	~_fso_information(){}

	//copy constructor
	_fso_information (const _fso_information& rhs) :
		m_wstr_fso_name(rhs.m_wstr_fso_name), 
		m_fso_type(rhs.m_fso_type),
		m_ui_fso_size(rhs.m_ui_fso_size),
		m_wc_hash_type(rhs.m_wc_hash_type),
		m_wstr_fso_hash(rhs.m_wstr_fso_hash)
	{}

	//move constructor
	_fso_information (_fso_information&& rhs) noexcept :
	    m_wstr_fso_name(std::move(rhs.m_wstr_fso_name)), 
		m_fso_type(rhs.m_fso_type),
		m_ui_fso_size(rhs.m_ui_fso_size),
		m_wc_hash_type(rhs.m_wc_hash_type),
		m_wstr_fso_hash(std::move(rhs.m_wstr_fso_hash))
	{}

	////assignment operator
	//_fso_information& operator=(_fso_information&& rhs)
	//{
	//	m_wstr_fso_name = std::move(rhs.m_wstr_fso_name);
	//	m_fso_type = std::move(rhs.m_fso_type);
	//	m_ui_fso_size = std::move(rhs.m_ui_fso_size);
	//	m_wc_hash_type = std::move(rhs.m_wc_hash_type);
	//	m_wstr_fso_hash = std::move(rhs.m_wstr_fso_hash);
	//
	//	return *this;
	//}

	_fso_information& operator=(const _fso_information& rhs)
	{
		m_wstr_fso_name = rhs.m_wstr_fso_name;
		m_fso_type = rhs.m_fso_type;
		m_ui_fso_size = rhs.m_ui_fso_size;
		m_wc_hash_type = rhs.m_wc_hash_type;
		m_wstr_fso_hash = rhs.m_wstr_fso_hash;
	
		return *this;
	}


	//the name of the fso [file system object]
	std::wstring m_wstr_fso_name = L"";
	//the type of the fso
	std::experimental::filesystem::file_type m_fso_type = std::experimental::filesystem::file_type::unknown;
	//the fso size
	unsigned int m_ui_fso_size = 0;
	//hash type used
	wc_HashType m_wc_hash_type = wc_HashType::WC_HASH_TYPE_NONE;
	//the hash of the fso
	std::wstring m_wstr_fso_hash = L"";
}fso_information;

//functions
deque<fso_information> getDirectoryContents(wstring& wstrDirectory);
void DirectoryContentsWorkThread();
void HashFileWorkThread();
int HashGetBlockSize(wc_HashType hash_type);
void getFileHash(fso_information& fiFileToHash);


//Shared data for threads
atomic<bool> g_a_shutdown = false;
atomic<unsigned short> g_a_directory_count = 0;

deque<wstring> g_dque_wstr_directories;
std::timed_mutex g_m_dque_wstr_directories;

deque<fso_information> g_dque_fi_contents;
std::timed_mutex g_m_dque_fi_contents;

//Worker thread function for retrieving directory contents
void DirectoryContentsWorkThread()
{
	fso_information fiAddFile;
	deque<wstring> dque_wstr_directories;
	deque<fso_information> dque_fi_contents;
	std::unique_lock<std::timed_mutex> lock_que_dc(g_m_dque_fi_contents, std::defer_lock);

	//continue execution while shutdown flag is set to false
	while (g_a_shutdown == false)
	{
		//Check to see if there are any directories to process, if not then check global (shared) queue for records to retrieve
		if (dque_wstr_directories.size() == 0)
		{
			std::lock_guard<std::timed_mutex> lock_que_d(g_m_dque_wstr_directories);

			//retrieve all directories queue'd to have contents returned
			g_dque_wstr_directories.swap(dque_wstr_directories);
		}

		//Check if anything to process, yield execution if nothing to process
		if (dque_wstr_directories.size() == 0)
		{
			this_thread::yield();
		}

		//Retrieve the contents for each of the directories
		for( wstring& wstrDirectory : dque_wstr_directories )
		{
			//retrieve the contents of the directory
			dque_fi_contents = getDirectoryContents(wstrDirectory);

			//acquire lock
			while (lock_que_dc.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//can't aquire the mutex, yield the thread
				this_thread::yield();
			}

			//move data in to global queue for processing
			for (fso_information& fiFile : dque_fi_contents)
			{
				g_dque_fi_contents.push_back(std::move(fiFile));
			}

			//unlock queue
			lock_que_dc.unlock();

			//clear the dque_fi_contents (which have all been moved)
			dque_fi_contents.clear();

			//decrement directory count
			g_a_directory_count--;
		}

		//clear the list of directories that was either just processed or is empty
		dque_wstr_directories.clear();

	}//end of while (g_a_shutdown == false)
}


deque<fso_information> getDirectoryContents(wstring& wstrDirectory)
{
	deque<fso_information> dque_fi_contents;

	//cout << "getFilesFromDirectory thread id: " << this_thread::get_id() << endl;

	//validate the directory exists 
	if (is_directory(wstrDirectory) == false)
	{
		return dque_fi_contents;
	}

	//iterate through each file in the directory using a range-based for-loop :-)
	for (directory_entry deObject : directory_iterator(wstrDirectory))
	{
		try
		{
			//Attempt to add the object with the size, if an exception occured it was most likely due to file_size
			switch (deObject.status().type())
			{
			case file_type::regular:
				dque_fi_contents.push_back(fso_information(deObject.path().generic_wstring(), 
														   file_type::regular,
														   static_cast<unsigned int>(file_size(deObject.path()))));
				//dcReturn.m_list_pair_ui_str.push_front(_make_ui_str_pair(file_size(deObject.path()), deObject.path().generic_wstring()));
				break;
			case file_type::directory:
				dque_fi_contents.push_back(fso_information(deObject.path().generic_wstring(), 
												           file_type::directory));
				break;
			}
		}
		catch (std::experimental::filesystem::filesystem_error& eCatch)
		{
			std::cout << eCatch.what() << endl;
		}

	}

	return dque_fi_contents;
}

//Get the Hash Block Size
int HashGetBlockSize(wc_HashType hash_type)
{
	int iHashBlockSize = 0;

	switch (hash_type)
	{
	case WC_HASH_TYPE_MD5:
		iHashBlockSize = MD5_BLOCK_SIZE;
		break;
	case WC_HASH_TYPE_SHA:
		iHashBlockSize = SHA_BLOCK_SIZE;
		break;
	case WC_HASH_TYPE_SHA256:
		iHashBlockSize = SHA256_BLOCK_SIZE;
		break;
	case WC_HASH_TYPE_SHA512:
		iHashBlockSize = SHA512_BLOCK_SIZE;
		break;
	}

	return iHashBlockSize;
}


deque<fso_information> g_dque_fi_hashfiles;
std::timed_mutex g_m_dque_hashfiles;

multimap<wstring, fso_information> g_mm_str_fi_hashedfiles;
std::timed_mutex g_m_mm_str_fi_hashedfiles;

atomic<unsigned short> g_a_hash_count = 0;


void HashFileWorkThread()
{
	deque<fso_information> deque_fi_hashfiles;
	std::unique_lock<std::timed_mutex> lock_mm_str_fi(g_m_mm_str_fi_hashedfiles, std::defer_lock);

	//continue execution while shutdown flag is set to false
	while (g_a_shutdown == false)
	{
		//Check if anything to process
		if (deque_fi_hashfiles.size() > 0)
		{
			int i_fso_to_process = static_cast<int>(deque_fi_hashfiles.size());

			//Retrieve the fso for each item needing a hash
			for( int ifso = 0; ifso < i_fso_to_process; ifso++ )
			{
				//TODO: allow programmatic selection of hash algorithm
				//modify the hash type to being MD5
				deque_fi_hashfiles[ifso].m_wc_hash_type = wc_HashType::WC_HASH_TYPE_MD5;

				//get a hash for the file associated with the fso_information object
				getFileHash(deque_fi_hashfiles[ifso]);
			}

			//aquire lock
			while (lock_mm_str_fi.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//can't aquire the mutex, yield the thread
				this_thread::yield();
			}

			//Move the fso 
			for (int ifso = 0; ifso < i_fso_to_process; ifso++)
			{
				//move data
				g_mm_str_fi_hashedfiles.insert(make_pair(deque_fi_hashfiles[ifso].m_wstr_fso_hash, std::move(deque_fi_hashfiles[ifso])));
			}
			
			//unlock queue
			lock_mm_str_fi.unlock();

			//decrement hash count
			g_a_hash_count -= i_fso_to_process;

			//clear the local deque which should contain empty fso
			deque_fi_hashfiles.clear();
		}
		else
		{
			//If there is nothing to process in the local queue 
			// then check global (shared) queue for records to retrieve
			std::lock_guard<std::timed_mutex> lock_que_f(g_m_dque_hashfiles);

			//retrieve all files requested to be hashed by performing a swap
			// this should be thread safe because of the aquired lock
			g_dque_fi_hashfiles.swap(deque_fi_hashfiles);
		}


		//Is there any work to do?
		if (deque_fi_hashfiles.size() == 0)
		{
			//Nothing to process, yield thread
			this_thread::yield();
		}


	}//end of while (g_a_shutdown == false)
}


//////////////////////////////////////////////////////////
// getFileHash
// Hash the specified file that is listed in the fso_information object after
// hashing the file, add the hash digest value to the fso_information object
//

void getFileHash(fso_information& fiFileToHash)
{
	//file stream vars
	uintmax_t uiBytesLeftInFile = 0;
	fstream fsOpenedFile;
	byte bFileBuffer[1024] = {}; //maximum input bytes is 1024 (should always be much more than the largest hash block size)

	//hash vars
	wc_HashAlg hashAlg; //hash structure being used for hash generation
	byte bHashDigest[128] = {}; //hash digest is a maximum of 64 bytes
	size_t sHashDigestSize = 0; //how large is the digest intended to be
	size_t sHashBlockSize = 0; //used to determine number of bytes to read from file at a time
	wstring wstrHashDigest; //Hash Digest in a wstring (to be returned)

	//validate the file size from the fso_information object
	if (fiFileToHash.m_ui_fso_size <= 0)
	{
		//either the variable is wrong or the file has no contents to hash
		return;
	}


	//validate the file exists, if not then exit the program early
	if (exists(fiFileToHash.m_wstr_fso_name) == true)
	{
		//open the file stream
		fsOpenedFile.open(fiFileToHash.m_wstr_fso_name, fstream::binary | fstream::in);

		//verify the file is opened and then retrieve the file contents for hashing
		if (fsOpenedFile.is_open() == false)
		{
			//the file didn't open correctly, cleanup the function
			goto cleanup;
		}
	}
	else
	{
		//the file doesn't exist
		goto cleanup;
	}


	//Get the Digest and Block Size
	sHashDigestSize = wc_HashGetDigestSize(fiFileToHash.m_wc_hash_type);
	sHashBlockSize = HashGetBlockSize(fiFileToHash.m_wc_hash_type);

	//Init the hash structure
	wc_HashInit(&hashAlg, fiFileToHash.m_wc_hash_type);

	//Set the bytes left to be read from the file
	uiBytesLeftInFile = fiFileToHash.m_ui_fso_size;

	//Stream in the file and create a hash from the file being streamed in
	// this method is to avoid massive allocations (especially for exceedingly large files)
	// and should still run fairly fast thanks to WolfSSL or WolfCrypto
	while (uiBytesLeftInFile > 0)
	{
		//read in contents from the file
		fsOpenedFile.read(reinterpret_cast<char*>(bFileBuffer), min(sHashBlockSize, uiBytesLeftInFile));

		//hash the contents
		wc_HashUpdate(&hashAlg, fiFileToHash.m_wc_hash_type, (const byte*)bFileBuffer, static_cast<word32>(min(sHashBlockSize, uiBytesLeftInFile)));

		//subtract the bytes read from uiBytesLeftInFile
		uiBytesLeftInFile -= min(sHashBlockSize, uiBytesLeftInFile);
	}

	//Get the completed hash
	wc_HashFinal(&hashAlg, fiFileToHash.m_wc_hash_type, bHashDigest);

	//Convert to a wstring
	wstrHashDigest = ByteArrayToHexWString(bHashDigest, sHashDigestSize);

	//copy the hash wstring for return
	fiFileToHash.m_wstr_fso_hash = wstrHashDigest;

cleanup:

	//close the file
	if (fsOpenedFile.is_open() == true)
	{
		fsOpenedFile.close();
	}

	return;
}


int main()
{
	multimap<wstring, fso_information> mmhashedfiles;
	map<unsigned int,fso_information> mapOfFileSizes; //Use to determine collision of file sizes
	map<wstring,fso_information> mapOfFileNames; //Use to list potential duplicate files (via their size only)
	deque<wstring> dque_wstr_directories;
	deque<fso_information> dque_fi_contents;
	deque<fso_information> dque_fi_filestohash;
	std::unique_lock<std::timed_mutex> lock_que_directories(g_m_dque_wstr_directories, std::defer_lock);
	std::unique_lock<std::timed_mutex> lock_que_files(g_m_dque_hashfiles, std::defer_lock);
	bool bFinishedProcessing = 0;

	//aquire lock
	lock_que_directories.lock();
	//push the first directory on
	g_dque_wstr_directories.push_back(L"c:\\windows");
	//increment work count
	g_a_directory_count++;
	//release the lock
	lock_que_directories.unlock();

	//kick off the worker thread for processing (or retrieving) directory contents
	thread directorycontents_thread_a = thread(DirectoryContentsWorkThread);
	//detach the thread so it can clean up once it finishes
	directorycontents_thread_a.detach();

	//kick off the first worker thread for creating secure hash of file contents
	thread hashfile_thread_a = thread(HashFileWorkThread);
	//detach the thread so it can clean up once it finishes
	hashfile_thread_a.detach();

	//kick off the second worker thread for creating secure hash of file contents
	thread hashfile_thread_b = thread(HashFileWorkThread);
	//detach the thread so it can clean up once it finishes
	hashfile_thread_b.detach();

	//kick off the second worker thread for creating secure hash of file contents
	thread hashfile_thread_c = thread(HashFileWorkThread);
	//detach the thread so it can clean up once it finishes
	hashfile_thread_c.detach();

	while (g_a_shutdown == false)
	{
		//Check directory contents queue for records to process, if empty then retrieve any records from the global queue
		if (dque_fi_contents.size() == 0)
		{
			std::lock_guard<std::timed_mutex> lock_que_contents(g_m_dque_fi_contents);

			//move the queued items to a local queue for processing of directory contents
			for (fso_information& fiContents : g_dque_fi_contents)
			{
				dque_fi_contents.push_back(std::move(fiContents));
			}

			//clear the global directory contents queue
			g_dque_fi_contents.clear();
		}

		//process all items that are currently in the directory contents queue
		for( fso_information& fiEntry : dque_fi_contents )
		{

			if (fiEntry.m_fso_type == file_type::directory)
			{
				//move only the string to queue of directories to be processed
				dque_wstr_directories.push_back(std::move(fiEntry.m_wstr_fso_name));
			}
			else if (fiEntry.m_fso_type == file_type::regular)
			{
				auto aInsertReturn = mapOfFileSizes.insert(make_pair(fiEntry.m_ui_fso_size, fiEntry));

				//check to see if a key with the file size already exists
				if (aInsertReturn.second == false)
				{
					//Insert based upon size failed, attempt to add to a new map using the filename as the key
					auto aExistingRecord = mapOfFileNames.insert(make_pair(aInsertReturn.first->second.m_wstr_fso_name, aInsertReturn.first->second));

					//Check to see if the insert was successful, which used the record that had 'blocked' insertion on the 
					// queue for hashing the contents of the file
					if (aExistingRecord.second == true)
					{
						//If the name of the file (from the blocking record) was inserted then it was a unique file name
						// then make sure to add it to queue of files to be hashed
						dque_fi_filestohash.push_back(aInsertReturn.first->second);

						//multimapOfPotentialDuplicates.insert(make_pair(aInsertReturn.first->first, aInsertReturn.first->second));
					}

					//queue the record that was blocked from insertion (which was based upon it's file size from the first map)
					dque_fi_filestohash.push_back(fiEntry);
					//multimapOfPotentialDuplicates.insert(aItem);
				}
			}
		}//for( fso_information fiEntry : dque_fi_contents )

		//clear the contents of the dque_fi_contents (that were just processed)
		dque_fi_contents.clear();

		 //move any directory fso_information objects in to global queue for processing
		if (dque_wstr_directories.size() > 0)
		{
			while (lock_que_directories.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//yield thread while waiting for lock
				this_thread::yield();
			}

			for (wstring& wstrDirectory : dque_wstr_directories)
			{
				g_dque_wstr_directories.push_back(std::move(wstrDirectory));
				g_a_directory_count++; //increment the directory count
			}

			//unlock queue
			lock_que_directories.unlock();

			//clear the directories to process
			dque_wstr_directories.clear();
		}

		//Check for files (from the directory contents) that are to be hashed
		if (dque_fi_filestohash.size() > 0)
		{
			//lock access to files [to hash] queue
			while (lock_que_files.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//yield thread while waiting for lock
				this_thread::yield();
			}

			for (fso_information& fifiletohash : dque_fi_filestohash)
			{
				g_dque_fi_hashfiles.push_back(std::move(fifiletohash));
				g_a_hash_count++;
			}

			//unlock queue
			lock_que_files.unlock();

			//clear the dque_fi_filestohash
			dque_fi_filestohash.clear();
		}


		//verify if there is no more work to be done, all threads finished processing
		if (dque_fi_contents.size() == 0 && g_a_directory_count == 0)
		{
			if (g_a_hash_count == 0)
			{
				//send the shutdown flag to the worker thread
				g_a_shutdown = true;
			}
		}
		else if (dque_fi_contents.size() == 0)
		{
			//there is work to be done, but nothing to process here so yield the thread
			this_thread::yield();
		}

	}//end  while (g_a_shutdown == false)

	for (auto aItem : g_mm_str_fi_hashedfiles)
	{
		cout << setw(10) << aItem.first << " | " << setw(10) << aItem.second.m_ui_fso_size << " | " << aItem.second.m_wstr_fso_name << endl;
	}

    return 0;
}

