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

using namespace std;
using namespace std::tr2::sys;

typedef list<pair<uintmax_t, string>> _list_pair_ui_str;
typedef multimap<uintmax_t, string> _multimap_ui_str;
typedef multimap<const uintmax_t, string> _multimap_cui_str;

typedef map<uintmax_t, string> _map_ui_str;
typedef map<const uintmax_t, string> _map_cui_str;

typedef map<string, uintmax_t> _map_str_ui;

typedef vector<string> _vector_str;

#define _make_ui_str_pair make_pair<uintmax_t, string>
#define _make_cui_str_pair make_pair<const uintmax_t, string>

#define _make_str_ui_pair make_pair<string, uintmax_t>
#define _make_str_cui_pair make_pair<string, const uintmax_t>

//structs
typedef struct _directory_contents
{
	//default constructor
	explicit _directory_contents()
	{
		//cout << "used the default constructor";
		//outputMemberMemoryLocation();
		//cout << endl;
	}

	~_directory_contents()
	{
		//cout << "called deconstructor";
		//outputMemberMemoryLocation();
		//cout << endl;
	}

	//copy constructor
	_directory_contents(const _directory_contents& rhs)
	{
		m_list_pair_ui_str = rhs.m_list_pair_ui_str;
		m_vector_str = rhs.m_vector_str;
		//cout << "used the copy constructor";
		//outputMemberMemoryLocation();
		//cout << endl;
	}

	//move constructor
	_directory_contents(_directory_contents&& rhs) noexcept
		: m_list_pair_ui_str(std::move(rhs.m_list_pair_ui_str)), m_vector_str(std::move(rhs.m_vector_str))
	{
		//cout << "used the move constructor";
		//outputMemberMemoryLocation();
		//cout << endl;
	}

	//assignment operator
	_directory_contents& operator=(_directory_contents&& rhs)
	{
		m_list_pair_ui_str = move(rhs.m_list_pair_ui_str);
		m_vector_str = move(rhs.m_vector_str);
		
		//cout << "used assignment operator=";
		//outputMemberMemoryLocation();
		//cout << endl;
		
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

//functions
directory_contents getDirectoryContents(string strDirectory);
void DirectoryContentsWorkThread();
void HashFileWorkThread();
int HashGetBlockSize(wc_HashType hash_type);



//Shared data for threads
atomic<bool> g_a_shutdown = false;
atomic<unsigned short> g_a_directory_count = 0;

queue<string> g_que_str_directories;
std::timed_mutex g_mquedirectories;

queue<directory_contents> g_que_directorycontents;
std::timed_mutex g_mquedirectorycontents;

//Worker thread function for retrieving directory contents
void DirectoryContentsWorkThread()
{
	directory_contents dcReturn;
	queue<string> que_str_directories;
	std::unique_lock<std::timed_mutex> lock_que_dc(g_mquedirectorycontents, std::defer_lock);

	//continue execution while shutdown flag is set to false
	while (g_a_shutdown == false)
	{
		//Check to see if there are any directories to process, if not then check global (shared) queue for records to retrieve
		if (que_str_directories.size() == 0)
		{
			std::lock_guard<std::timed_mutex> lock_que_directories(g_mquedirectories);

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


directory_contents getDirectoryContents(string strDirectory)
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
			dcReturn.m_list_pair_ui_str.push_front(_make_ui_str_pair(file_size(deObject.path()), deObject.path().generic_string()));
			break;
		case file_type::directory:
			dcReturn.m_vector_str.push_back(deObject.path().generic_string());
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


void HashFileWorkThread()
{



}


string getFileHash(wc_HashType hashType, string strFilePath)
{
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
			cout << "failed to open file: " << strFilePath.data() << endl;
		}
	}
	else
	{
		//the file doesn't exist
		cout << "error the file: " << strFilePath.data() << " was not found" << endl;
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

	//human readable output
	cout << vCmdLineArgs[0].c_str() << " hash of file " << pathHashFile.string().c_str() << endl;

	for (int ibyte = 0; ibyte < sHashDigestSize; ibyte++)
	{
		cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << int(bHashDigest[ibyte]);
	}

	cout << endl;

cleanup:

	//close the file
	if (fsHashFile.is_open() == true)
	{
		fsHashFile.close();
	}
}


int main()
{
	_multimap_cui_str multimapOfPotentialDuplicates;
	_map_ui_str mapOfFileSizes; //Use to determine collision of file sizes
	_map_str_ui mapOfFileNames; //Use to list potential duplicate files (via their size only)
	queue<directory_contents> que_directorycontents;
	std::unique_lock<std::timed_mutex> lock_que_directories(g_mquedirectories, std::defer_lock);
	bool bFinishedProcessing = 0;

	//aquire lock
	lock_que_directories.lock();
	//push the first directory on
	g_que_str_directories.push(string("c:\\"));
	//increment work count
	g_a_directory_count++;
	//release the lock
	lock_que_directories.unlock();

	//kick off the worker thread for processing (or retrieving) directory contents
	thread directorycontents_thread = thread(DirectoryContentsWorkThread);
	//detach the thread so it can clean up once it finishes
	directorycontents_thread.detach();

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

				for (string strDirectory : que_directorycontents.front().m_vector_str)
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
						// first map which inserts are based upon the file size
						if (aExistingRecord.second == true)
						{
							//If the name of the file (from the blocking record) was inserted then it was a unique file name
							// then make sure to add it to the multimap of files that are potentially duplicate files
							multimapOfPotentialDuplicates.insert(make_pair(aInsertReturn.first->first, aInsertReturn.first->second));
						}

						//add the record that was blocked from insertion (which was based upon it's file size from the first map)
						multimapOfPotentialDuplicates.insert(aItem);
					}
				}
			}

			//pop off the currently processed item
			que_directorycontents.pop();
		}//end while(que_directorycontents.size() > 0 )


		//verify if there is no more work to be done, all threads finished processing
		if (que_directorycontents.size() == 0 && g_a_directory_count == 0)
		{
			//send the shutdown flag to the worker thread
			g_a_shutdown = true;
		}
		else if (que_directorycontents.size() == 0)
		{
			//there is work to be done, but nothing to process here so yield the thread
			this_thread::yield();
		}

	}//end  while (g_a_shutdown == false)

	for (auto aItem : multimapOfPotentialDuplicates)
	{
		cout << setw(10) << aItem.first << " : " << aItem.second.c_str() << endl;
	}

    return 0;
}

