/* ========================================================================= *
 *                                                                           *
 *                      Laplacian Smoothing                                  *
 *                Old Dominion University and NSF                            *
 *                  Department of Cybersecurity                              *
 *                                                                           *
 *                                                                           *
 *                                                                           *
 *---------------------------------------------------------------------------*
 * This file uses OpenMesh and Microsoft SEAL library                        *
 *---------------------------------------------------------------------------*
 *Author: Justine Gausin                                                     *
\*===========================================================================*/
// Select mesh type (TriMesh) and kernel (ArrayKernel)
// and define my personal mesh type (MyMesh)


#include "examples.h"
using namespace seal;
using namespace std;


///We create a unique trait for the mesh 
typedef OpenMesh::TriMesh_ArrayKernelT<MyTraits>  MyMesh;


void smoothing ( int numberofsmoothing, string &inputfile,  string &outputfile)
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    /* OPENS THE MESH */
    
    MyMesh mesh;
    if (!OpenMesh::IO::read_mesh(mesh, inputfile)) 
    {
      std::cerr << "read error\n";
      exit(1);
    }
     // this vector stores the computed centers of gravity
    std::vector<MyMesh::Point>  cogs;
    std::vector<int> valencecount;

    std::vector<MyMesh::Point>::iterator cog_it;
    cogs.reserve(mesh.n_vertices());
    MyMesh::VertexIter          v_it, v_end(mesh.vertices_end());
    MyMesh::VertexVertexIter    vv_it;
    MyMesh::Point               cog;
    MyMesh::Point               currentvertex;
    int                         valence;
    double                      x,y,z;
    int                         valencehighest = 0;

    /*reserving  vector for the main pack*/
    vector<double> MainPack; 
    vector<vector<double>> Neighbors;


    // ----------------------------------------------------------------------------
    // SEAL DECLARATIONS: for this project we used a polymodulus degree of 16384. 
    // We can further test how fast the computation would be if we change the polumod in the future

    // ----------------------------------------------------------------------------
    print_example_banner("This is an official smoothing algorithm");
    

    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
    poly_modulus_degree, { 60, 40, 40,40,40,40,40,40, 60 }));  ///400 bit which is under the 438 max


    auto context = SEALContext::Create(parms);
    print_parameters(context);
    ///cout << endl;

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    //print_line(__LINE__);
    ///cout << "Number of slots: " << slot_count << endl;
    /* double scale1 = pow(2.0,40);
    Plaintext plain_coeff3, plain_coeff11;
    ckks_encoder.encode(3.14159265, scale1, plain_coeff3);
    Ciphertext x11_encrypted;
    encryptor.encrypt(plain_coeff3,x11_encrypted);
    vector<double> y1;
    decryptor.decrypt(x11_encrypted, plain_coeff3);
    ckks_encoder.decode(plain_coeff3, y1);
    print_vector(y1);*/



  for(int itr = 0; itr < numberofsmoothing; itr++)
    {
    cout << "Doing the " << itr+1 << " smoothing" <<endl;

    Neighbors.clear();
    MainPack.clear();
    valencecount.clear();

    int counter=0; 
    for (v_it=mesh.vertices_begin(); v_it!=v_end; ++v_it)
    {
      cogs.clear();
      counter++;

      currentvertex = mesh.point(*v_it);

      //////cout << currentvertex[0] << " " << currentvertex[1] << " " << currentvertex[2] << " " << endl;
      cog[0] = cog[1] = cog[2] = 0.0;
      valence = 0;
      MainPack.push_back(currentvertex[0]);
      MainPack.push_back(currentvertex[1]);
      MainPack.push_back(currentvertex[2]);
      for (vv_it=mesh.vv_iter(*v_it); vv_it.is_valid(); ++vv_it)
      {
        ++valence;
      }
      
      ///populate it three times for x y and z
      valencecount.push_back(valence);
      valencecount.push_back(valence);
      valencecount.push_back(valence);


      if (valence > valencehighest)
      {
          valencehighest = valence;
      }

    }
 
    /*create a number of pack vectors based on the highest valence count */
    ///cout << "highest valence count: --->>>>>>>>" << valencehighest << endl;
    for(int t = 0; t < valencehighest; t++)
    {
        vector<double> sidepacks;
        Neighbors.push_back(sidepacks);
    }
    

    /*-----------------------------------ITERATE BACK--------------------------------------  */

    size_t n;
  
    for (v_it=mesh.vertices_begin(), n = 0; v_it!=v_end, n < valencecount.size(); ++v_it, n+=3)
    {
      int l=0;
      /* if( valencecount[n] >= 9)
         {///cout <<  valencecount[n] << " ";}*/

       for (vv_it=mesh.vv_iter(*v_it); vv_it.is_valid(), l < valencecount[n]; ++vv_it, l++)
      {
        currentvertex = mesh.point( *vv_it );
        Neighbors[l].push_back(currentvertex[0]);
        Neighbors[l].push_back(currentvertex[1]);
        Neighbors[l].push_back(currentvertex[2]);
      }
      if(valencecount[n] < valencehighest) 
        {
            int diff = valencehighest - valencecount[n];
            
           /// ///cout << diff << " "; 
            for( int restofnums = (valencecount[n]); restofnums < valencehighest; restofnums++)
            {
                double j =0.0;
                Neighbors[restofnums].push_back(j);
                Neighbors[restofnums].push_back(j);
                Neighbors[restofnums].push_back(j);
            }   
        }

    }
    
    // ----------------------------------------------------------------------------
    ///                       WE BEGIN ENCRYPTING
    // ----------------------------------------------------------------------------

    /// We can push the main original packet to the back of the list of Neighbors
    /// However it increases the chance of corrupting the pack, thus we use two different packs 




    ///Reserve some vectors that can hold the Ciphertexts
    vector<Ciphertext> OriginalPacket; 
    vector<double> mainpack;
    vector<Ciphertext> ogpack;

    vector<vector<Ciphertext>> allpackets;
    vector<double> encryptionpacks(slot_count, 0.0);


    ///The slot is limited so we need to do the encryption in iterations
    size_t listof = Neighbors[0].size();
    ///cout << listof <<endl;
    int loops = (listof / slot_count) + 1;
    ///cout << loops << endl; 
    ///cout << "lets encrypt the  packet first" << endl;

     /* 
      since there is limited amount of slots in the encoding and encryption, we have to separate every 8192
      numbers into different Ciphertexts. Likewise, we try to only use 8190 of those slots within the slot_count.
      Because each point consist of an x , y, z and is encryted separately, we have to use a number divisible by 
      3 so that we dont lose vector components during a run off. 
    */

    for(size_t iterate = 0; iterate < Neighbors.size(); iterate++)
    {
        //////cout<< "iterate number-----------------------" << iterate << endl;
        OriginalPacket.clear();
        for( int z = 0; z < loops; z++ )
        {
            int position = 8190 * z;
            encryptionpacks.clear();
            if(z == (loops-1))
            {
                int sizel = Neighbors[iterate].size() - position;
                ///cout << "size of sizel is " << sizel << endl;
                for (size_t i = 0; i < slot_count-2; i++)
                {
                    encryptionpacks.push_back(Neighbors[iterate][position+i]);
                }
            }
            else
            {
                ///Slotcount -2 because 8190 blocks are used 
                for (size_t i = 0; i < (slot_count-2); i++)
                {
                    encryptionpacks.push_back(Neighbors[iterate][position+i]);
                
                }
               
            }
            /////cout << encryptionpacks.size() << endl;
            /////print_vector(encryptionpacks, 3, 7);
            auto scale = pow(2.0, 40);
            ///cout << "Encode and encrypt." << endl;
            Plaintext plain;
            ckks_encoder.encode(encryptionpacks, scale, plain);
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            OriginalPacket.push_back(encrypted);
        }
        Neighbors[iterate].clear();
        allpackets.push_back(OriginalPacket);
    }
    ///This is the main packet. we try to separate it with its neighbors due to the fact that it may be corrupted, as tested earlier. 
    for( int z = 0; z < loops; z++ )
        {
            int position = 8190 * z;
            mainpack.clear();
            if(z == (loops-1))
            {
                int sizel = MainPack.size() - position;
                ///cout << "size of sizel is " << sizel << endl;
                for (size_t i = 0; i < slot_count-2; i++)
                {
                    mainpack.push_back(MainPack[position+i]);
                }
            }
            else
            {
                ///Slotcount -2 because 8190 blocks are used 
                for (size_t i = 0; i < (slot_count-2); i++)
                {
                    mainpack.push_back(MainPack[position+i]);
                
                }
            }
            ///cout << mainpack.size() << endl;
            ///print_vector(mainpack, 3, 7);
            auto scale = pow(2.0, 40);
           /// ///cout << "Encode and encrypt." << endl;
            Plaintext plain;
            ckks_encoder.encode(mainpack, scale, plain);
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            ogpack.push_back(encrypted);
        }


  

    ////ADD all the neighbors in to packet[0] and leaving the last packet (thats the original packet)
    // ----------------------------------------------------------------------------------
    ///                       WE BEGIN THE OPERATIONS
    ///          Normally all operations should be done in the cloud instead of here
    // ----------------------------------------------------------------------------------
    for(size_t t=1; t < allpackets.size(); t++)
    {
      //////cout << "iterate number" << " " << t << endl;
        for(size_t len = 0; len < allpackets[0].size(); len++)
        {
            evaluator.add_inplace(allpackets[0][len], allpackets[t][len]);
        }
    }

    ////we divide based on the valence number per each vertex of packet[0]
    /// ----------------------------------------------------------------------------
    ///                       WE BEGIN ENCODING THE VALENCE
    ///      we divide based on the valence number per each vertex of packet[0]
    ///     To determine the barycenter we have to determine the reciprical of the valence
    ///                  Vc = 1/valence x ( ∑ all 1-ring neighbor vertices)
    /// ----------------------------------------------------------------------------                         
    vector<Plaintext> encoding;
    vector<double> encodervalence(slot_count, 0.0);
  
  ///cout << "loops"  << endl;
   for( int z = 0; z < loops; z++ )
    {
      encodervalence.clear();
      //////cout << z << endl;
      int position = 8190 * z;
      if(z == (loops-1))
        {
          int sizel = valencecount.size() - position;
          ///cout << "size of sizel is " << sizel << endl;
          for (int i = 0; i < sizel; i++)
          {
            double x = valencecount[position+i];
            double y = 1/x;
            encodervalence.push_back(y);
          }
          for (int i= sizel; i < int(slot_count-2); i++)
          {
             encodervalence.push_back(0.0);
          }
        }
      else
      {
        ///Slotcount -2 because 8190 blocks are used 
        for (size_t i = 0; i < (slot_count-2); i++)
          {
            double x = valencecount[position+i];
            double y = 1/x;

            encodervalence.push_back((y));    
          }
      }
      Plaintext plain;
      double scale = pow(2.0, 40);
      ///print_line(__LINE__);
      ///cout << "Encode input vector." << endl;
      /////print_vector(encodervalence, 10, 4);
      ckks_encoder.encode(encodervalence, scale, plain);
      encoding.push_back(plain);

    }

     ////we divide based on the valence number per each vertex of packet[0]
    /// ----------------------------------------------------------------------------
    ///                       FINISH SMOOTHING BY FINDING Vc
    ///                           Vi + k(Vc - Vi)
    ///                               k = .55
    /// ----------------------------------------------------------------------------   
    
    double LaplacianConstant = .55;
    Plaintext plainLaplacian;
    double scale = pow(2.0, 40);
    ckks_encoder.encode(LaplacianConstant, scale, plainLaplacian);


    /* 
      Store data in another ciphertext due to being susceptible to corruption in the vector<vector<ciphertext>> container.
      All the ///cout are important when we need to check if the param id and the scale are all the same.
      Adding ciphertext in Microsoft Seal requires that the scale and param id are the same and equal level.
    */

  ///Store data in another ciphertext due to it being corrupted in the vector<vector<ciphertext>> container
  vector<Ciphertext> blo;
  ///print_line(__LINE__);
    for(size_t i = 0; i < allpackets[0].size(); i++)
    {
     
       Ciphertext cipher;
        evaluator.multiply_plain_inplace(allpackets[0][i], encoding[i]);
        evaluator.negate(allpackets[0][i], cipher);
        ///cout << "    + cipher blocls: " << cipher.scale() << endl;
        evaluator.rescale_to_next_inplace(cipher);
        ///cout << "    + cipher blocls: " << cipher.scale() << endl;
        ///cout << "    + Modulus chain index for : "  << context->get_context_data(cipher.parms_id())->chain_index() << endl;
        ///cout << "    + Modulus chain index for ogpacker: "  << context->get_context_data(ogpack[i].parms_id())->chain_index() << endl;
        blo.push_back(cipher);
    }   

 
    ///cout << "size of the og pack is: " << ogpack.size() << " and the size of the all pack is " << blo.size() << endl;
   for(size_t i = 0; i < blo.size(); i++)
    {
      parms_id_type last_parms_id = blo[i].parms_id();  
      evaluator.mod_switch_to_inplace(ogpack[i], last_parms_id);
      evaluator.mod_switch_to_inplace(plainLaplacian, last_parms_id); 
      blo[i].scale() = pow(2.0, 40);
      evaluator.add_inplace(blo[i], ogpack[i]);
      evaluator.multiply_plain_inplace(blo[i], plainLaplacian);


    }
   
    for(size_t i = 0; i < blo.size(); i++)
    {
      evaluator.rescale_to_next_inplace(blo[i]);  
      parms_id_type last_parms_id = blo[i].parms_id();   
      evaluator.mod_switch_to_inplace(ogpack[i], last_parms_id);
      blo[i].scale() = pow(2.0, 40);
      evaluator.add_inplace(blo[i], ogpack[i]);
      
    }


 
    /// ----------------------------------------------------------------------------
    ///                      Decode
    ///                                   
    /// ----------------------------------------------------------------------------   
  
    ///first we populate the decoded message 
   
    vector<vector<double>> newVcenter;
    vector<double> newcenter;

    ///cout << " size of all the packets are " << allpackets.size() << endl;


    for(size_t i = 0; i < allpackets[0].size(); i++)
    {
        Plaintext plain;
        decryptor.decrypt(allpackets[0][i], plain);
        vector<double> result;
        ckks_encoder.decode(plain, result);
        newVcenter.push_back(result);
        ///print_vector(result, 3, 7);
    }

    ///clean up the 0's and padding 

    for(size_t im = 0; im < newVcenter.size(); im++)
    {
      for (size_t i = 0; i < (slot_count-2); i++)
        {
            newcenter.push_back(newVcenter[im][i]);
        }         
    }
    
    int sizeofthewholevector = listof;
    newcenter.erase((newcenter.begin()+sizeofthewholevector), newcenter.end());
  
    /// ----------------------------------------------------------------------------
    ///                      Create the new vertex points
    ///                                   
    /// ---------------------------------------------------------------------------- 


    ///Store the barycenter 

    vector<double>::iterator it;
    for (v_it=mesh.vertices_begin(), it = newcenter.begin();v_it!=v_end, it != newcenter.end(); ++v_it, it++)
    {
      cog[0] = (*it);
      it++;
      cog[1] =  *(it);
      it++;
      cog[2] = *(it);
      /////cout << cog[0] << " " << cog [1] << " " << cog[2] << "/ ";
      mesh.data(*v_it).set_cog(cog);
    }

    ///place them as the new point
    for (v_it=mesh.vertices_begin(); v_it!=v_end; ++v_it)
    {
      if (!mesh.is_boundary(*v_it))
        {mesh.set_point( *v_it, mesh.data(*v_it).cog());}
    }
  }
  time_end = chrono::high_resolution_clock::now();
  time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
  cout << "Done [" << time_diff.count() << " microseconds]" << endl;


    /// ----------------------------------------------------------------------------
    ///                     
    ///                             OUTPUT THE FILE
    ///                                   
    /// ---------------------------------------------------------------------------- 


  if ( ! OpenMesh::IO::write_mesh(mesh, outputfile) )
  {
      std::cerr << "Error: cannot write mesh to " << outputfile << std::endl;
  }

}



