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

//result of file hashing
typedef struct _file_information
{
	//default constructor
	explicit _file_information(){}

	~_file_information(){}

	//copy constructor
	_file_information(const _file_information& rhs) : 
		m_str_file(rhs.m_str_file), 
		m_str_file_hash(rhs.m_str_file_hash),
		m_ui_file_size(rhs.m_ui_file_size),
		m_wc_hash_type(rhs.m_wc_hash_type)
	{}

	//move constructor
	_file_information(_file_information&& rhs) noexcept :
	    m_str_file(std::move(rhs.m_str_file)), 
		m_str_file_hash(std::move(rhs.m_str_file_hash)),
		m_ui_file_size(std::move(rhs.m_ui_file_size)),
		m_wc_hash_type(std::move(rhs.m_wc_hash_type))
	{}

	//assignment operator
	_file_information& operator=(_file_information&& rhs)
	{
		m_str_file = move(rhs.m_str_file);
		m_str_file_hash = move(rhs.m_str_file_hash);
		m_ui_file_size = move(rhs.m_ui_file_size);
		m_wc_hash_type = move(rhs.m_wc_hash_type);

		return *this;
	}

	//the path of the file being hashed
	wstring m_str_file;
	//the hash of the file
	wstring m_str_file_hash;
	//the file size
	unsigned int m_ui_file_size;
	//hash type used
	wc_HashType m_wc_hash_type;
}file_information;

//functions
directory_contents getDirectoryContents(wstring strDirectory);
void DirectoryContentsWorkThread();
void HashFileWorkThread();
int HashGetBlockSize(wc_HashType hash_type);
file_information getFileHash(wc_HashType hashType, wstring strFilePath);


//Shared data for threads
atomic<bool> g_a_shutdown = false;
atomic<unsigned short> g_a_directory_count = 0;

queue<wstring> g_que_str_directories;
std::timed_mutex g_mquedirectories;

queue<directory_contents> g_que_directorycontents;
std::timed_mutex g_mquedirectorycontents;

//Worker thread function for retrieving directory contents
void DirectoryContentsWorkThread()
{
	directory_contents dcReturn;
	queue<wstring> que_str_directories;
	std::unique_lock<std::timed_mutex> lock_que_dc(g_mquedirectorycontents, std::defer_lock);

	//continue execution while shutdown flag is set to false
	while (g_a_shutdown == false)
	{
		//Check to see if there are any directories to process, if not then check global (shared) queue for records to retrieve
		if (que_str_directories.size() == 0)
		{
			std::lock_guard<std::timed_mutex> lock_que_d(g_mquedirectories);

			//retrieve all directories queue'd to have contents returned
			while (g_que_str_directories.size() > 0)
			{
				que_str_directories.push(g_que_str_directories.front());
				g_que_str_directories.pop();
			}
		}

		//Retrieve the contents for each of the directories
		while (que_str_directories.size() > 0)
		{
			dcReturn = getDirectoryContents(que_str_directories.front());
			que_str_directories.pop();

			//aquire lock
			while (lock_que_dc.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//can't aquire the mutex, yield the thread
				this_thread::yield();
			}

			//move data
			g_que_directorycontents.push(std::move(dcReturn));

			//unlock queue
			lock_que_dc.unlock();

			//decrement directory count
			g_a_directory_count--;
		}

		//Check if anything to process, yield execution if nothing to process
		if (que_str_directories.size() == 0)
		{
			this_thread::yield();
		}

	}//end of while (g_a_shutdown == false)
}


directory_contents getDirectoryContents(wstring strDirectory)
{
	directory_contents dcReturn;

	//cout << "getFilesFromDirectory thread id: " << this_thread::get_id() << endl;

	//validate the directory exists 
	if (is_directory(strDirectory) == false)
	{
		return dcReturn;
	}

	//iterate through each file in the directory using a range-based for-loop :-)
	for (directory_entry deObject : directory_iterator(strDirectory))
	{
		switch (deObject.status().type() )
		{
		case file_type::regular:
			dcReturn.m_list_pair_ui_str.push_front(_make_ui_str_pair(file_size(deObject.path()), deObject.path().generic_wstring()));
			break;
		case file_type::directory:
			dcReturn.m_vector_str.push_back(deObject.path().generic_wstring());
			break;
		}
	}

	return dcReturn;
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


queue<wstring> g_que_str_files;
std::timed_mutex g_m_quefiles;

multimap<wstring, file_information> g_mm_str_filehash;
std::timed_mutex g_m_mm_str_filehash;

atomic<unsigned short> g_a_hash_count = 0;


void HashFileWorkThread()
{
	file_information fh_return;
	queue<wstring> que_str_files;
	std::unique_lock<std::timed_mutex> lock_mm_str_fh(g_m_mm_str_filehash, std::defer_lock);

	//continue execution while shutdown flag is set to false
	while (g_a_shutdown == false)
	{
		//Check to see if there are any directories to process, if not then check global (shared) queue for records to retrieve
		if (que_str_files.size() == 0)
		{
			std::lock_guard<std::timed_mutex> lock_que_f(g_m_quefiles);

			//retrieve all directories queue'd to have contents returned
			while (g_que_str_files.size() > 0)
			{
				que_str_files.push(g_que_str_files.front());
				g_que_str_files.pop();
			}
		}

		//Retrieve the contents for each of the directories
		while (que_str_files.size() > 0)
		{
			fh_return = getFileHash(WC_HASH_TYPE_MD5, que_str_files.front());
			que_str_files.pop();

			//aquire lock
			while (lock_mm_str_fh.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//can't aquire the mutex, yield the thread
				this_thread::yield();
			}

			//move data
			g_mm_str_filehash.insert(make_pair(fh_return.m_str_file_hash, std::move(fh_return)));

			//unlock queue
			lock_mm_str_fh.unlock();

			//decrement directory count
			g_a_hash_count--;
		}

		//Check if anything to process, yield execution if nothing to process
		if (que_str_files.size() == 0)
		{
			this_thread::yield();
		}

	}//end of while (g_a_shutdown == false)
}


file_information getFileHash(wc_HashType hashType, wstring strFilePath)
{
	file_information fh_return;

	//file stream vars
	uintmax_t uiBytesLeftInFile = 0;
	uintmax_t uiFileSize = 0;
	fstream fsHashFile;
	byte bFileBuffer[1024] = {}; //maximum input bytes is 1024 (should always be much more than the largest hash block size)

	//hash vars
	wc_HashAlg hashAlg; //hash structure being used for hash generation
	byte bHashDigest[128] = {}; //hash digest is a maximum of 64 bytes
	size_t sHashDigestSize = 0; //how large is the digest intended to be
	size_t sHashBlockSize = 0; //used to determine number of bytes to read from file at a time
	wstring strHashDigest; //Hash Digest in a wstring (to be returned)

	//copy the input parameters for the return
	fh_return.m_str_file = strFilePath;
	fh_return.m_wc_hash_type = hashType;

	//validate the file exists, if not then exit the program early
	if (exists(strFilePath) == true)
	{
		//retrieve the file size
		uiFileSize = file_size(strFilePath);

		//open the file stream
		fsHashFile.open(strFilePath, fstream::binary | fstream::in);

		//verify the file is opened and then retrieve the file contents for hashing
		if (fsHashFile.is_open() == false)
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
	sHashDigestSize = wc_HashGetDigestSize(hashType);
	sHashBlockSize = HashGetBlockSize(hashType);

	//Init the hash structure
	wc_HashInit(&hashAlg, hashType);

	//Set the bytes left to be read from the file
	uiBytesLeftInFile = uiFileSize;

	//Stream in the file and create a hash from the file being streamed in
	// this method is to avoid massive allocations (especially for exceedingly large files)
	// and should still run fairly fast thanks to WolfSSL or WolfCrypto
	while (uiBytesLeftInFile > 0)
	{
		//read in contents from the file
		fsHashFile.read(reinterpret_cast<char*>(bFileBuffer), min(sHashBlockSize, uiBytesLeftInFile));

		//hash the contents
		wc_HashUpdate(&hashAlg, hashType, (const byte*)bFileBuffer, static_cast<word32>(min(sHashBlockSize, uiBytesLeftInFile)));

		//subtract the bytes read from uiBytesLeftInFile
		uiBytesLeftInFile -= min(sHashBlockSize, uiBytesLeftInFile);
	}

	//Get the completed hash
	wc_HashFinal(&hashAlg, hashType, bHashDigest);

	//Convert to a wstring
	strHashDigest = ByteArrayToHexWString(bHashDigest, sHashDigestSize);

	//copy the hash wstring for return
	fh_return.m_str_file_hash = strHashDigest;

	//TODO: make this less hacky (getting file size, instead the file_information struct should be handed around)
	fh_return.m_ui_file_size = static_cast<unsigned int>(file_size(fh_return.m_str_file));

cleanup:

	//close the file
	if (fsHashFile.is_open() == true)
	{
		fsHashFile.close();
	}

	return fh_return;
}


int main()
{
	_multimap_cui_str multimapOfPotentialDuplicates;
	multimap<wstring, file_information> mmHashedFiles;
	_map_ui_str mapOfFileSizes; //Use to determine collision of file sizes
	_map_str_ui mapOfFileNames; //Use to list potential duplicate files (via their size only)
	queue<directory_contents> que_directorycontents;
	queue<wstring> que_files_to_hash;
	std::unique_lock<std::timed_mutex> lock_que_directories(g_mquedirectories, std::defer_lock);
	std::unique_lock<std::timed_mutex> lock_que_files(g_m_quefiles, std::defer_lock);
	bool bFinishedProcessing = 0;

	//aquire lock
	lock_que_directories.lock();
	//push the first directory on
	g_que_str_directories.push(wstring(L"D:\\DCIM\\Pictures"));
	//increment work count
	g_a_directory_count++;
	//release the lock
	lock_que_directories.unlock();

	//kick off the worker thread for processing (or retrieving) directory contents
	thread directorycontents_thread = thread(DirectoryContentsWorkThread);
	//detach the thread so it can clean up once it finishes
	directorycontents_thread.detach();

	//kick off the first worker thread for creating secure hash of file contents
	thread hashfile_thread_a = thread(HashFileWorkThread);
	//detach the thread so it can clean up once it finishes
	hashfile_thread_a.detach();

	//kick off the second worker thread for creating secure hash of file contents
	thread hashfile_thread_b = thread(HashFileWorkThread);
	//detach the thread so it can clean up once it finishes
	hashfile_thread_b.detach();


	while (g_a_shutdown == false)
	{
		//Check directory contents queue for records to process, if empty then retrieve any records from the global queue
		if (que_directorycontents.size() == 0)
		{
			std::lock_guard<std::timed_mutex> lock_que_directorycontents(g_mquedirectorycontents);

			//move the queued items to a local queue for processing of directory contents
			while (g_que_directorycontents.size() > 0)
			{
				que_directorycontents.push(std::move(g_que_directorycontents.front()));
				g_que_directorycontents.pop();
			}
		}

		//process all items that are currently in the directory contents queue
		while(que_directorycontents.size() > 0 )
		{

			//retrieve list of directories to send to worker thread for processing
			if (que_directorycontents.front().m_vector_str.size() > 0)
			{
				while (lock_que_directories.try_lock_for(chrono::milliseconds(1)) == false)
				{
					//yield thread while waiting for lock
					this_thread::yield();
				}

				for (wstring strDirectory : que_directorycontents.front().m_vector_str)
				{
					g_que_str_directories.push(strDirectory);
					g_a_directory_count++; //increment the directory count
				}

				//unlock queue
				lock_que_directories.unlock();
			}

			//Process all the files with associated sizes in the list
			for (auto aItem : que_directorycontents.front().m_list_pair_ui_str)
			{
				if (aItem.first >= (1024 * 1024))
				{
					//insert based with a key based on the file size
					auto aInsertReturn = mapOfFileSizes.insert(aItem);

					//check to see if a key with the file size already exists
					if (aInsertReturn.second == false)
					{
						//Insert based upon size failed, attempt to add to a new map using the filename as the key
						auto aExistingRecord = mapOfFileNames.insert(make_pair(aInsertReturn.first->second, aInsertReturn.first->first));

						//Check to see if the insert was successful, which used the record that had 'blocked' insertion on the 
						// queue for hashing the contents of the file
						if (aExistingRecord.second == true)
						{
							//If the name of the file (from the blocking record) was inserted then it was a unique file name
							// then make sure to add it to queue of files to be hashed
							que_files_to_hash.push(aInsertReturn.first->second);

							//multimapOfPotentialDuplicates.insert(make_pair(aInsertReturn.first->first, aInsertReturn.first->second));
						}

						//queue the record that was blocked from insertion (which was based upon it's file size from the first map)
						que_files_to_hash.push(aItem.second);
						//multimapOfPotentialDuplicates.insert(aItem);
					}
				}
			}

			//pop off the currently processed item
			que_directorycontents.pop();
		}//end while(que_directorycontents.size() > 0 )

		//Check for files (from the directory contents) that are to be hashed
		if (que_files_to_hash.size() > 0)
		{
			//lock access to files [to hash] queue
			while (lock_que_files.try_lock_for(chrono::milliseconds(1)) == false)
			{
				//yield thread while waiting for lock
				this_thread::yield();
			}

			while (que_files_to_hash.size() > 0)
			{
				g_que_str_files.push(que_files_to_hash.front());
				g_a_hash_count++;

				//remove the front item from the local queue
				que_files_to_hash.pop();
			}

			//unlock queue
			lock_que_files.unlock();
		}


		//verify if there is no more work to be done, all threads finished processing
		if (que_directorycontents.size() == 0 && g_a_directory_count == 0)
		{
			if (g_a_hash_count == 0)
			{
				//send the shutdown flag to the worker thread
				g_a_shutdown = true;
			}
		}
		else if (que_directorycontents.size() == 0)
		{
			//there is work to be done, but nothing to process here so yield the thread
			this_thread::yield();
		}

	}//end  while (g_a_shutdown == false)

	for (auto aItem : g_mm_str_filehash)
	{
		cout << setw(10) << aItem.first << " | " << setw(10) << aItem.second.m_ui_file_size << aItem.second.m_str_file << endl;
	}

    return 0;
}

