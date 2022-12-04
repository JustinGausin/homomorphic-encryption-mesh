// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main(int argc, char **argv)
{
    
    #ifdef SEAL_VERSION
        cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    #endif
    
    // check command line options
    if (argc != 4) 
    {
        cerr << "Usage: ------------------->>" << argv[0] << " #-of-iterations infile outfile\n";
        cerr << "Example: ------------------->>" << argv[0] << " 2 example.stl output.stl\n";

        return 1;
    }

    while (true)
    {
    
        string inputfile = argv[2];
        string outputfile = argv[3];
         int numberofsmoothing= stoi(argv[1]);

        
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| This program run the smoothing algorithm                |" << endl;
        cout << "|                                                         |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Examples                   | Source Files               |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. CKKS Smoothing Encrypt  | source.cpp                 |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

        int selection = 0;
        bool invalid = true;
        do
        {
            cout << endl << "> Run example (1) or exit (0): ";
            if (!(cin >> selection))
            {
                invalid = false;
            }
            else if (selection < 0 || selection > 1)
            {
                invalid = false;
            }
            else
            {
                invalid = true;
            }
            if (!invalid)
            {
                cout << "  [Beep~~] Invalid option: type 0 ~ 1" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!invalid);

        switch (selection)
            {
        case 1:
            smoothing(numberofsmoothing, inputfile, outputfile);
            break;

        case 0:
            return 0;
        }
    }

    return 0;
}
