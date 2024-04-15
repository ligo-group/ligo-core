#include <fc/crypto/elliptic.hpp>

#include <fc/crypto/base58.hpp>
#include <fc/crypto/hmac.hpp>
#include <fc/crypto/openssl.hpp>
#include <fc/crypto/sha512.hpp>

#include <fc/fwd_impl.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>

#include <assert.h>
#include <secp256k1.h>
#include <fc/crypto/hex.hpp>
#if _WIN32
# include <malloc.h>
#else
# include <alloca.h>
#endif

#include "_elliptic_impl_priv.hpp"
#include <secp256k1_rangeproof.h>
#include <secp256k1_recovery.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
namespace fc { namespace ecc {
    namespace detail
    {
        const secp256k1_context* _get_context() {
            //static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN );
            static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            return ctx;
        }

        void _init_lib() {
            static const secp256k1_context* ctx = _get_context();
            static int init_o = init_openssl();
            (void)ctx;
        }

        class public_key_impl
        {
            public:
                public_key_impl() BOOST_NOEXCEPT
                {
                    _init_lib();
                }

                public_key_impl( const public_key_impl& cpy ) BOOST_NOEXCEPT
                    : _key( cpy._key )
                {
                    _init_lib();
                }

                public_key_data _key;
        };

        typedef fc::array<char,37> chr37;
        chr37 _derive_message( const public_key_data& key, int i );
        fc::sha256 _left( const fc::sha512& v );
        fc::sha256 _right( const fc::sha512& v );
        const ec_group& get_curve();
        const private_key_secret& get_curve_order();
        const private_key_secret& get_half_curve_order();
    }

    static const public_key_data empty_pub;
    static const private_key_secret empty_priv;

    fc::sha512 private_key::get_shared_secret( const public_key& other )const
    {
      FC_ASSERT( my->_key != empty_priv );
      FC_ASSERT( other.my->_key != empty_pub );
      public_key_data pub(other.my->_key);
	  secp256k1_pubkey new_key;
	  FC_ASSERT(secp256k1_ec_pubkey_parse(detail::_get_context(), &new_key, (unsigned char*)pub.begin(), pub.size()));

      FC_ASSERT( secp256k1_ec_pubkey_tweak_mul( detail::_get_context(), &new_key, (unsigned char*) my->_key.data() ) );
	  public_key old_pub(new_key);
	  std::reverse(new_key.data, new_key.data + 32);

	  
      return fc::sha512::hash((char*)old_pub.serialize().data + 1, 32 );
    }


    public_key::public_key() {}

    public_key::public_key( const public_key &pk ) : my( pk.my ) {}

    public_key::public_key( public_key &&pk ) : my( std::move( pk.my ) ) {}

    public_key::~public_key() {}

    public_key& public_key::operator=( const public_key& pk )
    {
        my = pk.my;
        return *this;
    }

    public_key& public_key::operator=( public_key&& pk )
    {
        my = pk.my;
        return *this;
    }

    bool public_key::valid()const
    {
      return my->_key != empty_pub;
    }

    public_key public_key::add( const fc::sha256& digest )const
    {
        FC_ASSERT( my->_key != empty_pub );
        //public_key_data new_key;
		secp256k1_pubkey new_key;
		secp256k1_ec_pubkey_parse(detail::_get_context(), &new_key, (const unsigned char *)my->_key.begin(), 33);
        /*memcpy( new_key.begin(), my->_key.begin(), new_key.size() );*/
        FC_ASSERT( secp256k1_ec_pubkey_tweak_add( detail::_get_context(), &new_key, (unsigned char*) digest.data() ) );
        return public_key( new_key );
    }

    std::string public_key::to_base58() const
    {
        FC_ASSERT( my->_key != empty_pub );
        return to_base58( my->_key );
    }

    public_key_data public_key::serialize()const
    {
        FC_ASSERT( my->_key != empty_pub );
        return my->_key;
    }

    public_key_point_data public_key::serialize_ecc_point()const
    {
        FC_ASSERT( my->_key != empty_pub );
        public_key_point_data dat;
        unsigned int pk_len = my->_key.size();
        memcpy( dat.begin(), my->_key.begin(), pk_len );
		secp256k1_pubkey pub;
        FC_ASSERT(secp256k1_ec_pubkey_parse( detail::_get_context(), &pub,(unsigned char *) dat.begin(), pk_len ) );
		//dat.data[0] = 0x04;
		size_t outlen = 65;
		FC_ASSERT(secp256k1_ec_pubkey_serialize(detail::_get_context(), (unsigned char *)&dat.data, &outlen, &pub, SECP256K1_EC_UNCOMPRESSED));
		//memcpy(&dat.data[1], pub.data, 64);
        //FC_ASSERT( pk_len == dat.size() );
        return dat;
    }

    public_key::public_key( const public_key_point_data& dat )
    {
        const char* front = &dat.data[0];
        if( *front == 0 ){}
        else
        {
            EC_KEY *key = EC_KEY_new_by_curve_name( NID_secp256k1 );
            key = o2i_ECPublicKey( &key, (const unsigned char**)&front, sizeof(dat) );
            FC_ASSERT( key );
            EC_KEY_set_conv_form( key, POINT_CONVERSION_COMPRESSED );
            unsigned char* buffer = (unsigned char*) my->_key.begin();
            i2o_ECPublicKey( key, &buffer ); // FIXME: questionable memory handling
            EC_KEY_free( key );
        }
    }

    public_key::public_key( const public_key_data& dat )
    {
        my->_key = dat;
    }

	public_key::public_key(const secp256k1_pubkey& dat)
	{
		size_t outputlen=33;
		secp256k1_ec_pubkey_serialize(detail::_get_context(),(unsigned char*) my->_key.begin(), &outputlen, &dat, SECP256K1_EC_COMPRESSED);

	}

    public_key::public_key( const compact_signature& c, const fc::sha256& digest, bool check_canonical )
    {
        int nV = c.data[0];
        if (nV<27 || nV>=35)
            FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );

        if( check_canonical )
        {
            FC_ASSERT( is_canonical( c ), "signature is not canonical" );
        }

		size_t pk_len=33;
		int recid = (nV - 27-4) ;
		secp256k1_ecdsa_recoverable_signature new_sig;
		secp256k1_ecdsa_recoverable_signature_parse_compact(detail::_get_context(),&new_sig, c.begin() + 1,recid);
		/*memcpy(new_sig.data, c.begin() + 1, 64);
		new_sig.data[64] = recid;*/

		secp256k1_pubkey rec_pub;
		/*char new_digest[32];
		memcpy(new_digest, digest.data(), 32);
		std::reverse(new_digest, new_digest + 32);*/
		FC_ASSERT(secp256k1_ecdsa_recover(detail::_get_context(), &rec_pub, &new_sig, (unsigned char*)digest.data()));
		FC_ASSERT(secp256k1_ec_pubkey_serialize(detail::_get_context(), (unsigned char*)my->_key.begin(), &pk_len, &rec_pub, SECP256K1_EC_COMPRESSED));
		//printf("recover pub key %s\n", fc::to_hex((char*)my->_key.begin(), 33).c_str());
        //FC_ASSERT( secp256k1_ecdsa_recover_compact( detail::_get_context(), (unsigned char*) digest.data(), (unsigned char*) c.begin() + 1, (unsigned char*) my->_key.begin(), (int*) &pk_len, 1, (*c.begin() - 27) & 3 ) );
        FC_ASSERT( pk_len == my->_key.size() );
    }

    extended_public_key::extended_public_key( const public_key& k, const fc::sha256& c,
                                              int child, int parent, uint8_t depth )
        : public_key(k), c(c), child_num(child), parent_fp(parent), depth(depth) { }

    extended_public_key extended_public_key::derive_normal_child(int i) const
    {
        hmac_sha512 mac;
        public_key_data key = serialize();

        const detail::chr37 data = detail::_derive_message( key, i );
        fc::sha512 l = mac.digest( c.data(), c.data_size(), data.begin(), data.size() );
        fc::sha256 left = detail::_left(l);
        FC_ASSERT( left < detail::get_curve_order() );
		secp256k1_pubkey new_key;
		FC_ASSERT(secp256k1_ec_pubkey_parse(detail::_get_context(), &new_key, (unsigned char*)key.begin(), key.size()));
        FC_ASSERT( secp256k1_ec_pubkey_tweak_add( detail::_get_context(), &new_key, (unsigned char*) left.data() ) > 0 );
        // FIXME: check validity - if left + key == infinity then invalid
        extended_public_key result( key, detail::_right(l), i, fingerprint(), depth + 1 );
        return result;
    }








//    static void print(const unsigned char* data) {
//        for (int i = 0; i < 32; i++) {
//            printf("%02x", *data++);
//        }
//    }
//
//    static void print(private_key_secret key) {
//        print((unsigned char*) key.data());
//    }
//
//    static void print(public_key_data key) {
//        print((unsigned char*) key.begin() + 1);
//    }


//        printf("K: "); print(P); printf("\n");

        // prod == c^-1 * d

        // accu == prod * P == c^-1 * d * P

        // accu == c^-1 * a * P + Q

        // accu == c^-1 * a * P + Q + b*G

        // prod == Kx
        // prod == Kx * a
        // prod == (Kx * a)^-1

        // accu == (c^-1 * a * P + Q + b*G) * (Kx * a)^-1

//        printf("T: "); print(accu); printf("\n");

    extended_private_key::extended_private_key( const private_key& k, const sha256& c,
                                                int child, int parent, uint8_t depth )
        : private_key(k), c(c), child_num(child), parent_fp(parent), depth(depth) { }

    extended_private_key extended_private_key::private_derive_rest( const fc::sha512& hash,
                                                                    int i) const
    {
        fc::sha256 left = detail::_left(hash);
        FC_ASSERT( left < detail::get_curve_order() );
        FC_ASSERT( secp256k1_ec_privkey_tweak_add( detail::_get_context(), (unsigned char*) left.data(), (unsigned char*) get_secret().data() ) > 0 );
        extended_private_key result( private_key::regenerate( left ), detail::_right(hash),
                                     i, fingerprint(), depth + 1 );
        return result;

//        printf("a: "); print(a); printf("\n");
//        printf("b: "); print(b); printf("\n");
//        printf("c: "); print(c); printf("\n");
//        printf("d: "); print(d); printf("\n");
//        printf("P: "); print(p); printf("\n");
//        printf("Q: "); print(q); printf("\n");

//        printf("hash: "); print(hash); printf("\n");
//        printf("blinded: "); print(a); printf("\n");

//        printf("p: "); print(p_inv); printf("\n");

//        printf("q: "); print(q); printf("\n");

//        printf("blind_sig: "); print(p); printf("\n");



//        printf("unblinded: "); print(result.begin() + 33); printf("\n");
//                } else {
//                    printf("Candidate: "); print( pubkey ); printf("\n");
    }

     commitment_type blind( const blind_factor_type& blind, uint64_t value )
     {
        secp256k1_pedersen_commitment result;
        FC_ASSERT( secp256k1_pedersen_commit( detail::_get_context(), &result, (unsigned char*)&blind, value, secp256k1_generator_h) );
		commitment_type ret;
		memcpy(ret.begin(), result.data, 33);
        return ret;
     }

     blind_factor_type blind_sum( const std::vector<blind_factor_type>& blinds_in, uint32_t non_neg )
     {
        blind_factor_type result;
        std::vector<const unsigned char*> blinds(blinds_in.size());
        for( uint32_t i = 0; i < blinds_in.size(); ++i ) blinds[i] = (const unsigned char*)&blinds_in[i];
        FC_ASSERT( secp256k1_pedersen_blind_sum( detail::_get_context(), (unsigned char*)&result, blinds.data(), blinds_in.size(), non_neg ) );
        return result;
     }

     /**  verifies taht commnits + neg_commits + excess == 0 */
     bool            verify_sum( const std::vector<commitment_type>& commits_in, const std::vector<commitment_type>& neg_commits_in, int64_t excess )
     {
        std::vector<secp256k1_pedersen_commitment> commits(commits_in.size());
		for (uint32_t i = 0; i < commits_in.size(); ++i) {
			secp256k1_pedersen_commitment ret;
			memcpy(ret.data, commits_in[i].begin(), commits_in[i].size());
			commits[i] = ret;
		}
        std::vector<secp256k1_pedersen_commitment> neg_commits(neg_commits_in.size());
		for (uint32_t i = 0; i < neg_commits_in.size(); ++i) {
			secp256k1_pedersen_commitment ret;
			memcpy(ret.data, neg_commits_in[i].begin(), neg_commits_in[i].size());
			neg_commits[i] = ret;
		}
		secp256k1_pedersen_commitment ret;
		memcpy(ret.data, commits.data(), commits.size());
        return secp256k1_pedersen_verify_tally( detail::_get_context(), (const secp256k1_pedersen_commitment * const*)commits.data(),commits.size(), (const secp256k1_pedersen_commitment * const*)neg_commits.data(), neg_commits.size() );
     }

     bool            verify_range( uint64_t& min_val, uint64_t& max_val, const commitment_type& commit, const std::vector<char>& proof )
     {
		 secp256k1_pedersen_commitment ret;
		 memcpy(ret.data, commit.begin(), commit.size());
        return secp256k1_rangeproof_verify( detail::_get_context(), &min_val, &max_val, &ret, (const unsigned char*)proof.data(), proof.size(),NULL,0,secp256k1_generator_h );
     }

     std::vector<char>    range_proof_sign( uint64_t min_value, 
                                       const commitment_type& commit, 
                                       const blind_factor_type& commit_blind, 
                                       const blind_factor_type& nonce,
                                       int8_t base10_exp,
                                       uint8_t min_bits,
                                       uint64_t actual_value
                                     )
     {
        size_t proof_len = 5134; 
        std::vector<char> proof(proof_len);
		secp256k1_pedersen_commitment ret;
		memcpy(ret.data, commit.begin(), commit.size());
        FC_ASSERT( secp256k1_rangeproof_sign( detail::_get_context(), 
                                              (unsigned char*)proof.data(), 
                                              &proof_len, min_value, 
                                              &ret,
                                              (const unsigned char*)&commit_blind, 
                                              (const unsigned char*)&nonce, 
                                              base10_exp, min_bits, actual_value, NULL,0,NULL,0, secp256k1_generator_h) );
        proof.resize(proof_len);
        return proof;
     }


     bool            verify_range_proof_rewind( blind_factor_type& blind_out,
                                                uint64_t& value_out,
                                                string& message_out, 
                                                const blind_factor_type& nonce,
                                                uint64_t& min_val, 
                                                uint64_t& max_val, 
                                                commitment_type commit, 
                                                const std::vector<char>& proof )
     {
        char msg[4096];
        size_t  mlen = 0;
		secp256k1_pedersen_commitment ret;
		memcpy(ret.data, commit.begin(), commit.size());
        FC_ASSERT( secp256k1_rangeproof_rewind( detail::_get_context(), 
                                                (unsigned char*)&blind_out,
                                                &value_out,
                                                (unsigned char*)msg,
                                                &mlen,
                                                (const unsigned char*)&nonce,
                                                &min_val,
                                                &max_val,
                                                &ret,
                                                (const unsigned char*)proof.data(),
			proof.size(), NULL, 0,
			secp256k1_generator_h));

        message_out = std::string( msg, mlen );
        return true;
     }

     range_proof_info range_get_info( const std::vector<char>& proof )
     {
        range_proof_info result;
        FC_ASSERT( secp256k1_rangeproof_info( detail::_get_context(), 
                                              (int*)&result.exp, 
                                              (int*)&result.mantissa, 
                                              (uint64_t*)&result.min_value, 
                                              (uint64_t*)&result.max_value, 
                                              (const unsigned char*)proof.data(), 
                                              (int)proof.size() ) );

        return result;
     }


	 int convert_pubkey_to_p2tr(const public_key &pub, unsigned char* x_only_key) {
		 fc::sha256 sha2;
		 secp256k1_xonly_pubkey base_point;
		 if ((secp256k1_xonly_pubkey_parse(detail::_get_context(), &base_point, (const unsigned char *)&pub.serialize_ecc_point().data[1])) == 0) {
			 return 0;
		 }
		 secp256k1_pubkey out;
		 fc::uint256 taghash;
		 taghash = fc::sha256::hash("TapTweak", 8);
		 //printf("taghash: %s\n", taghash.str().c_str());
		 fc::sha256::encoder enc;
		 enc.write(taghash.data(), taghash.data_size());
		 enc.write(taghash.data(), taghash.data_size());
		 /*enc << taghash << taghash;*/
		 enc.write(&pub.serialize().data[1], 32);
		 fc::uint256 tweak = enc.result();
		 //printf("tweak_hash: %s\n", tweak.str().c_str());
		 if (secp256k1_xonly_pubkey_tweak_add(detail::_get_context(), &out, &base_point, (unsigned char *)tweak.data()) == 0) {
			 return 0;
		 }
		 int parity = -1;

		 secp256k1_xonly_pubkey out_xonly;
		 if (secp256k1_xonly_pubkey_from_pubkey(detail::_get_context(), &out_xonly, &parity, &out) == 0) {
			 return 0;
		 }
		 return secp256k1_xonly_pubkey_serialize( detail::_get_context(), x_only_key, &out_xonly);
	 }
	 int x_only_parse_check(unsigned char *x_only_key){
		 secp256k1_xonly_pubkey base_point;
		 return secp256k1_xonly_pubkey_parse(detail::_get_context(), &base_point, (const unsigned char *)x_only_key);
		  
	 }

} }
